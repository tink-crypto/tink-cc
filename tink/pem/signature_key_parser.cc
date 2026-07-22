// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "tink/pem/signature_key_parser.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/base/nullability.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "tink/internal/ssl_unique_ptr.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#endif
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/secret_buffer.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/signature/internal/ml_dsa_pem.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/util/secret_data.h"

ABSL_POINTERS_DEFAULT_NONNULL

namespace tink_pem {
namespace {

using ::crypto::tink::BigInteger;
using ::crypto::tink::EcdsaParameters;
using ::crypto::tink::EcdsaPrivateKey;
using ::crypto::tink::EcdsaPublicKey;
using ::crypto::tink::EcPoint;
using ::crypto::tink::Ed25519Parameters;
using ::crypto::tink::Ed25519PrivateKey;
using ::crypto::tink::Ed25519PublicKey;
using ::crypto::tink::MlDsaParameters;
using ::crypto::tink::MlDsaPublicKey;
using ::crypto::tink::PartialKeyAccessToken;
using ::crypto::tink::RestrictedData;
using ::crypto::tink::RsaSsaPkcs1Parameters;
using ::crypto::tink::RsaSsaPkcs1PrivateKey;
using ::crypto::tink::RsaSsaPkcs1PublicKey;
using ::crypto::tink::RsaSsaPssParameters;
using ::crypto::tink::RsaSsaPssPrivateKey;
using ::crypto::tink::RsaSsaPssPublicKey;
using ::crypto::tink::SecretData;
using ::crypto::tink::SecretKeyAccessToken;
using ::crypto::tink::internal::BignumToSecretData;
using ::crypto::tink::internal::BignumToString;
using ::crypto::tink::internal::CallWithCoreDumpProtection;
using ::crypto::tink::internal::SslUniquePtr;

constexpr int kEd25519PublicKeySizeInBytes = 32;
using Ed25519PublicKeyBytes = std::array<uint8_t, kEd25519PublicKeySizeInBytes>;

int NoopFailingPassphraseCallback(char*, int, int, void*) { return -1; }

absl::StatusOr<SslUniquePtr<EVP_PKEY>> PemToEvpPublicKey(
    absl::string_view pem_public_key) {
  SslUniquePtr<BIO> bssl_evp_pkey_bio(BIO_new(BIO_s_mem()));
  BIO_write(bssl_evp_pkey_bio.get(), pem_public_key.data(),
            pem_public_key.size());
  SslUniquePtr<EVP_PKEY> /*absl_nullable - not yet supported*/ bssl_evp_pkey(
      PEM_read_bio_PUBKEY(bssl_evp_pkey_bio.get(), /*out=*/nullptr,
                          /*cb=*/&NoopFailingPassphraseCallback,
                          /*userdata=*/nullptr));
  if (bssl_evp_pkey == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "PEM Public Key parsing failed");
  }
  return bssl_evp_pkey;
}

absl::StatusOr<SslUniquePtr<EVP_PKEY>> PemToEvpPrivateKey(
    absl::string_view pem_private_key) {
  SslUniquePtr<BIO> bssl_evp_pkey_bio(BIO_new(BIO_s_mem()));
  CallWithCoreDumpProtection([&]() {
    BIO_write(bssl_evp_pkey_bio.get(), pem_private_key.data(),
              pem_private_key.size());
  });

  SslUniquePtr<EVP_PKEY> /*absl_nullable - not yet supported*/ bssl_evp_pkey(
      CallWithCoreDumpProtection([&]() -> EVP_PKEY* {
        return PEM_read_bio_PrivateKey(bssl_evp_pkey_bio.get(), /*out=*/nullptr,
                                       /*cb=*/&NoopFailingPassphraseCallback,
                                       /*userdata=*/nullptr);
      }));
  if (bssl_evp_pkey == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "PEM Private Key parsing failed");
  }
  return std::move(bssl_evp_pkey);
}

// ================== ECDSA ==================

absl::StatusOr<EcdsaParameters::CurveType> CurveTypeFromBoringSslEcGroup(
    const EC_GROUP* group) {
  switch (EC_GROUP_get_curve_name(group)) {
    case NID_X9_62_prime256v1:
      return EcdsaParameters::CurveType::kNistP256;
    case NID_secp384r1:
      return EcdsaParameters::CurveType::kNistP384;
    case NID_secp521r1:
      return EcdsaParameters::CurveType::kNistP521;
    default:
      return absl::Status(absl::StatusCode::kUnimplemented,
                          "Unsupported elliptic curve");
  }
}

size_t FieldElementSizeInBytes(const EC_GROUP* group) {
  unsigned degree_bits = EC_GROUP_get_degree(group);
  return (degree_bits + 7) / 8;
}

absl::StatusOr<crypto::tink::EcPoint> EcPointFromEcKey(const EC_KEY* ec_key) {
  SslUniquePtr<BIGNUM> x_coordinate(BN_new());
  SslUniquePtr<BIGNUM> y_coordinate(BN_new());
  const EC_POINT* public_point = EC_KEY_get0_public_key(ec_key);
  const EC_GROUP* ec_group = EC_KEY_get0_group(ec_key);
  if (EC_POINT_get_affine_coordinates(ec_group, public_point,
                                      x_coordinate.get(), y_coordinate.get(),
                                      nullptr) != 1) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to get affine coordinates");
  }
  ABSL_ASSIGN_OR_RETURN(
      std::string x_string,
      BignumToString(x_coordinate.get(), FieldElementSizeInBytes(ec_group)));
  ABSL_ASSIGN_OR_RETURN(
      std::string y_string,
      BignumToString(y_coordinate.get(), FieldElementSizeInBytes(ec_group)));
  return EcPoint(BigInteger(x_string), BigInteger(y_string));
}

absl::StatusOr<EcdsaPrivateKey> ParseEcdsaPrivateKey(
    absl::string_view pem_private_key, const EcdsaParameters& parameters,
    SecretKeyAccessToken secret_key_access,
    PartialKeyAccessToken partial_key_access) {
  if (parameters.GetVariant() != EcdsaParameters::Variant::kNoPrefix) {
    return absl::InvalidArgumentError(
        "PEM parsing is only supported for no-prefix variants.");
  }
  ABSL_ASSIGN_OR_RETURN(SslUniquePtr<EVP_PKEY> bssl_evp_pkey,
                        PemToEvpPrivateKey(pem_private_key));
  // Not owning.
  const EC_KEY* /*absl_nullable - not yet supported*/ bssl_ec_key =
      EVP_PKEY_get0_EC_KEY(bssl_evp_pkey.get());
  if (bssl_ec_key == nullptr || CallWithCoreDumpProtection([&]() {
                                  return EC_KEY_check_key(bssl_ec_key);
                                }) != 1) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid ECDSA key");
  }

  const EC_GROUP* /*absl_nullable - not yet supported*/ ec_group = EC_KEY_get0_group(bssl_ec_key);
  if (ec_group == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Null group provided");
  }
  ABSL_ASSIGN_OR_RETURN(EcdsaParameters::CurveType curve,
                        CurveTypeFromBoringSslEcGroup(ec_group));
  if (curve != parameters.GetCurveType()) {
    return absl::InvalidArgumentError(
        "EC curve in PEM does not match parameters.");
  }

  // Public key.
  ABSL_ASSIGN_OR_RETURN(EcPoint public_point, EcPointFromEcKey(bssl_ec_key));
  ABSL_ASSIGN_OR_RETURN(EcdsaPublicKey public_key,
                        EcdsaPublicKey::Create(parameters, public_point,
                                               /*id_requirement=*/std::nullopt,
                                               partial_key_access));

  // Private key.
  const BIGNUM* priv_key = EC_KEY_get0_private_key(bssl_ec_key);
  ABSL_ASSIGN_OR_RETURN(
      SecretData && priv,
      BignumToSecretData(priv_key,
                         BN_num_bytes(EC_GROUP_get0_order(ec_group))));
  RestrictedData private_key_value(std::move(priv), secret_key_access);
  ABSL_ASSIGN_OR_RETURN(EcdsaPrivateKey && private_key,
                        EcdsaPrivateKey::Create(public_key, private_key_value,
                                                partial_key_access));
  return private_key;
}

absl::StatusOr<EcdsaPublicKey> ParseEcdsaPublicKey(
    absl::string_view pem_public_key, const EcdsaParameters& parameters,
    PartialKeyAccessToken partial_key_access) {
  if (parameters.GetVariant() != EcdsaParameters::Variant::kNoPrefix) {
    return absl::InvalidArgumentError(
        "PEM parsing is only supported for no-prefix variants.");
  }
  ABSL_ASSIGN_OR_RETURN(SslUniquePtr<EVP_PKEY> bssl_evp_pubkey,
                        PemToEvpPublicKey(pem_public_key));
  // Not owning.
  const EC_KEY* /*absl_nullable - not yet supported*/ bssl_ec_key =
      EVP_PKEY_get0_EC_KEY(bssl_evp_pubkey.get());
  if (bssl_ec_key == nullptr || EC_KEY_check_key(bssl_ec_key) != 1) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid ECDSA key");
  }

  const EC_GROUP* /*absl_nullable - not yet supported*/ ec_group = EC_KEY_get0_group(bssl_ec_key);
  if (ec_group == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Null group provided");
  }
  ABSL_ASSIGN_OR_RETURN(EcdsaParameters::CurveType curve,
                        CurveTypeFromBoringSslEcGroup(ec_group));
  if (curve != parameters.GetCurveType()) {
    return absl::InvalidArgumentError(
        "EC curve in PEM does not match parameters.");
  }

  // Public key.
  ABSL_ASSIGN_OR_RETURN(EcPoint public_point, EcPointFromEcKey(bssl_ec_key));
  ABSL_ASSIGN_OR_RETURN(EcdsaPublicKey public_key,
                        EcdsaPublicKey::Create(parameters, public_point,
                                               /*id_requirement=*/std::nullopt,
                                               partial_key_access));
  return public_key;
}

// ================== Ed25519 ==================

absl::StatusOr<Ed25519PublicKeyBytes> BsslEd25519PublicKeyFromEvpKey(
    const EVP_PKEY* bssl_evp_pkey) {
  Ed25519PublicKeyBytes raw_key;
  size_t raw_key_len = raw_key.size();
  if (EVP_PKEY_get_raw_public_key(bssl_evp_pkey, raw_key.data(),
                                  &raw_key_len) != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Failed to get raw public key");
  }
  if (raw_key_len != kEd25519PublicKeySizeInBytes) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Invalid raw public key length");
  }
  return raw_key;
}

absl::StatusOr<Ed25519PrivateKey> ParseEd25519PrivateKey(
    absl::string_view pem_private_key, const Ed25519Parameters& parameters,
    SecretKeyAccessToken secret_key_access,
    PartialKeyAccessToken partial_key_access) {
  if (parameters.GetVariant() != Ed25519Parameters::Variant::kNoPrefix) {
    return absl::InvalidArgumentError(
        "PEM parsing is only supported for no-prefix variants.");
  }
  ABSL_ASSIGN_OR_RETURN(SslUniquePtr<EVP_PKEY> bssl_evp_pkey,
                        PemToEvpPrivateKey(pem_private_key));

  if (EVP_PKEY_id(bssl_evp_pkey.get()) != EVP_PKEY_ED25519) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid Ed25519 private key");
  }

  ABSL_ASSIGN_OR_RETURN(Ed25519PublicKeyBytes raw_pub_key,
                        BsslEd25519PublicKeyFromEvpKey(bssl_evp_pkey.get()));

  crypto::tink::internal::SecretBuffer raw_priv_key_buffer(32);
  size_t raw_priv_key_len = raw_priv_key_buffer.size();
  int get_raw_priv_key_status = CallWithCoreDumpProtection([&]() {
    return EVP_PKEY_get_raw_private_key(
        bssl_evp_pkey.get(), raw_priv_key_buffer.data(), &raw_priv_key_len);
  });
  if (get_raw_priv_key_status != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Failed to get raw private key");
  }
  if (raw_priv_key_len != 32) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Invalid raw private key length");
  }

  // Convert SecretBuffer to SecretData.
  SecretData raw_priv_key = crypto::tink::util::internal::AsSecretData(
      std::move(raw_priv_key_buffer));

  ABSL_ASSIGN_OR_RETURN(
      Ed25519PublicKey public_key,
      Ed25519PublicKey::Create(
          parameters,
          absl::string_view(reinterpret_cast<const char*>(raw_pub_key.data()),
                            raw_pub_key.size()),
          /*id_requirement=*/std::nullopt, partial_key_access));

  RestrictedData private_key_value(std::move(raw_priv_key), secret_key_access);
  return Ed25519PrivateKey::Create(public_key, private_key_value,
                                   partial_key_access);
}

absl::StatusOr<Ed25519PublicKey> ParseEd25519PublicKey(
    absl::string_view pem_public_key, const Ed25519Parameters& parameters,
    PartialKeyAccessToken partial_key_access) {
  if (parameters.GetVariant() != Ed25519Parameters::Variant::kNoPrefix) {
    return absl::InvalidArgumentError(
        "PEM parsing is only supported for no-prefix variants.");
  }
  ABSL_ASSIGN_OR_RETURN(SslUniquePtr<EVP_PKEY> bssl_evp_pubkey,
                        PemToEvpPublicKey(pem_public_key));

  if (EVP_PKEY_id(bssl_evp_pubkey.get()) != EVP_PKEY_ED25519) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid Ed25519 public key");
  }

  ABSL_ASSIGN_OR_RETURN(Ed25519PublicKeyBytes raw_pub_key,
                        BsslEd25519PublicKeyFromEvpKey(bssl_evp_pubkey.get()));

  return Ed25519PublicKey::Create(
      parameters,
      absl::string_view(reinterpret_cast<const char*>(raw_pub_key.data()),
                        raw_pub_key.size()),
      /*id_requirement=*/std::nullopt, partial_key_access);
}

// ================== ML-DSA ==================

absl::StatusOr<MlDsaPublicKey> ParseMlDsaPublicKey(
    absl::string_view pem_public_key, const MlDsaParameters& parameters,
    PartialKeyAccessToken partial_key_access) {
  if (parameters.GetVariant() != MlDsaParameters::Variant::kNoPrefix) {
    return absl::InvalidArgumentError(
        "PEM parsing is only supported for no-prefix variants.");
  }
  std::string public_key_bytes;
  switch (parameters.GetInstance()) {
    case MlDsaParameters::Instance::kMlDsa44: {
      ABSL_ASSIGN_OR_RETURN(
          public_key_bytes,
          crypto::tink::internal::ParseMldsa44PublicKey(pem_public_key));
      break;
    }
    case MlDsaParameters::Instance::kMlDsa65: {
      ABSL_ASSIGN_OR_RETURN(
          public_key_bytes,
          crypto::tink::internal::ParseMldsa65PublicKey(pem_public_key));
      break;
    }
    case MlDsaParameters::Instance::kMlDsa87: {
      ABSL_ASSIGN_OR_RETURN(
          public_key_bytes,
          crypto::tink::internal::ParseMldsa87PublicKey(pem_public_key));
      break;
    }
    default:
      return absl::InvalidArgumentError("Unsupported ML-DSA instance type");
  }

  ABSL_ASSIGN_OR_RETURN(MlDsaPublicKey public_key,
                        MlDsaPublicKey::Create(parameters, public_key_bytes,
                                               /*id_requirement=*/std::nullopt,
                                               partial_key_access));
  return public_key;
}

// ================== RSA ==================

absl::StatusOr<BigInteger> ExtractAndValidateModulusFromBsslRsa(
    const RSA* rsa, int expected_modulus_size_in_bits,
    const BigInteger& expected_public_exponent) {
  const BIGNUM *n, *e;
  RSA_get0_key(rsa, &n, &e, /*out_d=*/nullptr);
  if (n == nullptr || e == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "RSA key is missing modulus or public exponent");
  }

  int n_size = BN_num_bytes(n);
  if (n_size * 8 != expected_modulus_size_in_bits) {
    return absl::InvalidArgumentError(
        "Modulus size in PEM does not match parameters.");
  }

  // Check public exponent matches parameters.
  ABSL_ASSIGN_OR_RETURN(std::string e_str, BignumToString(e, BN_num_bytes(e)));
  if (BigInteger(e_str) != expected_public_exponent) {
    return absl::InvalidArgumentError(
        "Public exponent in PEM does not match parameters.");
  }

  ABSL_ASSIGN_OR_RETURN(std::string n_str, BignumToString(n, n_size));
  return BigInteger(n_str);
}

struct RsaPrivateKeyComponents {
  SecretData p;
  SecretData q;
  SecretData dp;
  SecretData dq;
  SecretData d;
  SecretData q_inv;
};

absl::StatusOr<RsaPrivateKeyComponents> ExtractRsaPrivateKeyComponents(
    const RSA* rsa) {
  const BIGNUM *n, *d, *p, *q, *dmp1, *dmq1, *iqmp;
  RSA_get0_key(rsa, &n, /*out_e=*/nullptr, &d);
  RSA_get0_factors(rsa, &p, &q);
  RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

  if (d == nullptr || p == nullptr || q == nullptr || dmp1 == nullptr ||
      dmq1 == nullptr || iqmp == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "RSA key is missing required private parameters");
  }

  int n_size = BN_num_bytes(n);
  int p_size = BN_num_bytes(p);
  int q_size = BN_num_bytes(q);

  RsaPrivateKeyComponents components;
  ABSL_ASSIGN_OR_RETURN(components.p, BignumToSecretData(p, p_size));
  ABSL_ASSIGN_OR_RETURN(components.q, BignumToSecretData(q, q_size));
  ABSL_ASSIGN_OR_RETURN(components.dp, BignumToSecretData(dmp1, p_size));
  ABSL_ASSIGN_OR_RETURN(components.dq, BignumToSecretData(dmq1, q_size));
  ABSL_ASSIGN_OR_RETURN(components.d, BignumToSecretData(d, n_size));
  ABSL_ASSIGN_OR_RETURN(components.q_inv, BignumToSecretData(iqmp, p_size));
  return components;
}

// ================== RSA-SSA-PSS ==================

absl::StatusOr<RsaSsaPssPublicKey> BsslRsaToRsaSsaPssPublicKey(
    const RSA* rsa, const RsaSsaPssParameters& parameters,
    PartialKeyAccessToken partial_key_access) {
  ABSL_ASSIGN_OR_RETURN(BigInteger modulus,
                        ExtractAndValidateModulusFromBsslRsa(
                            rsa, parameters.GetModulusSizeInBits(),
                            parameters.GetPublicExponent()));
  return RsaSsaPssPublicKey::Create(parameters, modulus,
                                    /*id_requirement=*/std::nullopt,
                                    partial_key_access);
}

absl::StatusOr<RsaSsaPssPrivateKey> ParseRsaSsaPssPrivateKey(
    absl::string_view pem_private_key, const RsaSsaPssParameters& parameters,
    SecretKeyAccessToken secret_key_access,
    PartialKeyAccessToken partial_key_access) {
  if (parameters.GetVariant() != RsaSsaPssParameters::Variant::kNoPrefix) {
    return absl::InvalidArgumentError(
        "PEM parsing is only supported for no-prefix variants.");
  }
  ABSL_ASSIGN_OR_RETURN(SslUniquePtr<EVP_PKEY> bssl_evp_pkey,
                        PemToEvpPrivateKey(pem_private_key));

  // Not owning.
  const RSA* /*absl_nullable - not yet supported*/ rsa = EVP_PKEY_get0_RSA(bssl_evp_pkey.get());
  if (rsa == nullptr ||
      CallWithCoreDumpProtection([&]() { return RSA_check_key(rsa); }) != 1) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "Invalid RSA key");
  }

  ABSL_ASSIGN_OR_RETURN(
      RsaSsaPssPublicKey public_key,
      BsslRsaToRsaSsaPssPublicKey(rsa, parameters, partial_key_access));
  ABSL_ASSIGN_OR_RETURN(RsaPrivateKeyComponents components,
                        ExtractRsaPrivateKeyComponents(rsa));

  RsaSsaPssPrivateKey::Builder builder;
  builder.SetPublicKey(public_key)
      .SetPrimeP(RestrictedData(std::move(components.p), secret_key_access))
      .SetPrimeQ(RestrictedData(std::move(components.q), secret_key_access))
      .SetPrimeExponentP(
          RestrictedData(std::move(components.dp), secret_key_access))
      .SetPrimeExponentQ(
          RestrictedData(std::move(components.dq), secret_key_access))
      .SetPrivateExponent(
          RestrictedData(std::move(components.d), secret_key_access))
      .SetCrtCoefficient(
          RestrictedData(std::move(components.q_inv), secret_key_access));
  return builder.Build(partial_key_access);
}

absl::StatusOr<RsaSsaPssPublicKey> ParseRsaSsaPssPublicKey(
    absl::string_view pem_public_key, const RsaSsaPssParameters& parameters,
    PartialKeyAccessToken partial_key_access) {
  if (parameters.GetVariant() != RsaSsaPssParameters::Variant::kNoPrefix) {
    return absl::InvalidArgumentError(
        "PEM parsing is only supported for no-prefix variants.");
  }
  ABSL_ASSIGN_OR_RETURN(SslUniquePtr<EVP_PKEY> bssl_evp_pubkey,
                        PemToEvpPublicKey(pem_public_key));
  // Not owning.
  const RSA* /*absl_nullable - not yet supported*/ rsa = EVP_PKEY_get0_RSA(bssl_evp_pubkey.get());
  if (rsa == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid RSA public key");
  }
  return BsslRsaToRsaSsaPssPublicKey(rsa, parameters, partial_key_access);
}

// ================== RSA-SSA-PKCS1 ==================

absl::StatusOr<RsaSsaPkcs1PublicKey> BsslRsaToRsaSsaPkcs1PublicKey(
    const RSA* rsa, const RsaSsaPkcs1Parameters& parameters,
    PartialKeyAccessToken partial_key_access) {
  ABSL_ASSIGN_OR_RETURN(BigInteger modulus,
                        ExtractAndValidateModulusFromBsslRsa(
                            rsa, parameters.GetModulusSizeInBits(),
                            parameters.GetPublicExponent()));
  return RsaSsaPkcs1PublicKey::Create(parameters, modulus,
                                      /*id_requirement=*/std::nullopt,
                                      partial_key_access);
}

absl::StatusOr<RsaSsaPkcs1PrivateKey> ParseRsaSsaPkcs1PrivateKey(
    absl::string_view pem_private_key, const RsaSsaPkcs1Parameters& parameters,
    SecretKeyAccessToken secret_key_access,
    PartialKeyAccessToken partial_key_access) {
  if (parameters.GetVariant() != RsaSsaPkcs1Parameters::Variant::kNoPrefix) {
    return absl::InvalidArgumentError(
        "PEM parsing is only supported for no-prefix variants.");
  }
  ABSL_ASSIGN_OR_RETURN(SslUniquePtr<EVP_PKEY> bssl_evp_pkey,
                        PemToEvpPrivateKey(pem_private_key));

  // Not owning.
  const RSA* /*absl_nullable - not yet supported*/ rsa = EVP_PKEY_get0_RSA(bssl_evp_pkey.get());
  if (rsa == nullptr ||
      CallWithCoreDumpProtection([&]() { return RSA_check_key(rsa); }) != 1) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "Invalid RSA key");
  }

  ABSL_ASSIGN_OR_RETURN(
      RsaSsaPkcs1PublicKey public_key,
      BsslRsaToRsaSsaPkcs1PublicKey(rsa, parameters, partial_key_access));
  ABSL_ASSIGN_OR_RETURN(RsaPrivateKeyComponents components,
                        ExtractRsaPrivateKeyComponents(rsa));

  RsaSsaPkcs1PrivateKey::Builder builder;
  builder.SetPublicKey(public_key)
      .SetPrimeP(RestrictedData(std::move(components.p), secret_key_access))
      .SetPrimeQ(RestrictedData(std::move(components.q), secret_key_access))
      .SetPrimeExponentP(
          RestrictedData(std::move(components.dp), secret_key_access))
      .SetPrimeExponentQ(
          RestrictedData(std::move(components.dq), secret_key_access))
      .SetPrivateExponent(
          RestrictedData(std::move(components.d), secret_key_access))
      .SetCrtCoefficient(
          RestrictedData(std::move(components.q_inv), secret_key_access));
  return builder.Build(partial_key_access);
}

absl::StatusOr<RsaSsaPkcs1PublicKey> ParseRsaSsaPkcs1PublicKey(
    absl::string_view pem_public_key, const RsaSsaPkcs1Parameters& parameters,
    PartialKeyAccessToken partial_key_access) {
  if (parameters.GetVariant() != RsaSsaPkcs1Parameters::Variant::kNoPrefix) {
    return absl::InvalidArgumentError(
        "PEM parsing is only supported for no-prefix variants.");
  }
  ABSL_ASSIGN_OR_RETURN(SslUniquePtr<EVP_PKEY> bssl_evp_pubkey,
                        PemToEvpPublicKey(pem_public_key));
  // Not owning.
  const RSA* /*absl_nullable - not yet supported*/ rsa = EVP_PKEY_get0_RSA(bssl_evp_pubkey.get());
  if (rsa == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid RSA public key");
  }
  return BsslRsaToRsaSsaPkcs1PublicKey(EVP_PKEY_get0_RSA(bssl_evp_pubkey.get()),
                                       parameters, partial_key_access);
}

}  // namespace

absl::StatusOr<crypto::tink::EcdsaPrivateKey> PemToEcdsaPrivateKey(
    absl::string_view pem_private_key,
    const crypto::tink::EcdsaParameters& parameters,
    crypto::tink::SecretKeyAccessToken secret_key_access,
    crypto::tink::PartialKeyAccessToken partial_key_access) {
  return ParseEcdsaPrivateKey(pem_private_key, parameters, secret_key_access,
                              partial_key_access);
}

absl::StatusOr<crypto::tink::Ed25519PrivateKey> PemToEd25519PrivateKey(
    absl::string_view pem_private_key,
    const crypto::tink::Ed25519Parameters& parameters,
    crypto::tink::SecretKeyAccessToken secret_key_access,
    crypto::tink::PartialKeyAccessToken partial_key_access) {
  return ParseEd25519PrivateKey(pem_private_key, parameters, secret_key_access,
                                partial_key_access);
}

absl::StatusOr<RsaSsaPssPrivateKey> PemToRsaSsaPssPrivateKey(
    absl::string_view pem_private_key, const RsaSsaPssParameters& parameters,
    SecretKeyAccessToken secret_key_access,
    PartialKeyAccessToken partial_key_access) {
  return ParseRsaSsaPssPrivateKey(pem_private_key, parameters,
                                  secret_key_access, partial_key_access);
}

absl::StatusOr<RsaSsaPkcs1PrivateKey> PemToRsaSsaPkcs1PrivateKey(
    absl::string_view pem_private_key, const RsaSsaPkcs1Parameters& parameters,
    SecretKeyAccessToken secret_key_access,
    PartialKeyAccessToken partial_key_access) {
  return ParseRsaSsaPkcs1PrivateKey(pem_private_key, parameters,
                                    secret_key_access, partial_key_access);
}

absl::StatusOr<crypto::tink::EcdsaPublicKey> PemToEcdsaPublicKey(
    absl::string_view pem_public_key, const EcdsaParameters& parameters,
    PartialKeyAccessToken partial_key_access) {
  return ParseEcdsaPublicKey(pem_public_key, parameters, partial_key_access);
}

absl::StatusOr<crypto::tink::Ed25519PublicKey> PemToEd25519PublicKey(
    absl::string_view pem_public_key,
    const crypto::tink::Ed25519Parameters& parameters,
    crypto::tink::PartialKeyAccessToken partial_key_access) {
  return ParseEd25519PublicKey(pem_public_key, parameters, partial_key_access);
}

absl::StatusOr<crypto::tink::MlDsaPublicKey> PemToMlDsaPublicKey(
    absl::string_view pem_public_key,
    const crypto::tink::MlDsaParameters& parameters,
    crypto::tink::PartialKeyAccessToken partial_key_access) {
  return ParseMlDsaPublicKey(pem_public_key, parameters, partial_key_access);
}

absl::StatusOr<crypto::tink::RsaSsaPssPublicKey> PemToRsaSsaPssPublicKey(
    absl::string_view pem_public_key,
    const crypto::tink::RsaSsaPssParameters& parameters,
    crypto::tink::PartialKeyAccessToken partial_key_access) {
  return ParseRsaSsaPssPublicKey(pem_public_key, parameters,
                                 partial_key_access);
}

absl::StatusOr<crypto::tink::RsaSsaPkcs1PublicKey> PemToRsaSsaPkcs1PublicKey(
    absl::string_view pem_public_key,
    const crypto::tink::RsaSsaPkcs1Parameters& parameters,
    crypto::tink::PartialKeyAccessToken partial_key_access) {
  return ParseRsaSsaPkcs1PublicKey(pem_public_key, parameters,
                                   partial_key_access);
}

}  // namespace tink_pem
