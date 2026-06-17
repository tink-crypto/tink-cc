// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/internal/testing/composite_ml_dsa_test_util.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/log/absl_log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "openssl/bn.h"
#include "openssl/mldsa.h"
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/secret_buffer.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/composite_ml_dsa_private_key.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/signature/internal/testing/rsa_ssa_pkcs1_test_vectors.h"
#include "tink/signature/internal/testing/rsa_ssa_pss_test_vectors.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/signature/signature_private_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

const BigInteger& kF4 = *new BigInteger(std::string("\x1\0\x1", 3));  // 65537

absl::Status NewRsaKeyPairF4(int modulus_size_in_bits,
                             internal::RsaPrivateKey* private_key,
                             internal::RsaPublicKey* public_key) {
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  if (BN_set_u64(e.get(), RSA_F4) != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Could not set RSA exponent.");
  }
  return internal::NewRsaKeyPair(modulus_size_in_bits, e.get(), private_key,
                                 public_key);
}

std::unique_ptr<SignaturePrivateKey> GenerateEd25519PrivateKeyOrDie() {
  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ABSL_CHECK_OK(key_pair);
  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix);
  ABSL_CHECK_OK(parameters);
  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *parameters, (*key_pair)->public_key,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<Ed25519PrivateKey> private_key = Ed25519PrivateKey::Create(
      *public_key,
      RestrictedData((*key_pair)->private_key, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return std::make_unique<Ed25519PrivateKey>(*private_key);
}

std::unique_ptr<SignaturePrivateKey> GenerateEcdsaPrivateKeyOrDie(
    subtle::EllipticCurveType subtle_curve_type,
    EcdsaParameters::CurveType ecdsa_curve_type,
    EcdsaParameters::HashType hash_type) {
  absl::StatusOr<internal::EcKey> key_pair =
      internal::NewEcKey(subtle_curve_type);
  ABSL_CHECK_OK(key_pair);
  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(ecdsa_curve_type)
          .SetHashType(hash_type)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters);
  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters,
      EcPoint(BigInteger(key_pair->pub_x), BigInteger(key_pair->pub_y)),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key,
      RestrictedData(key_pair->priv, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return std::make_unique<EcdsaPrivateKey>(*private_key);
}

std::unique_ptr<SignaturePrivateKey> GenerateRsaPss3072PrivateKeyOrDie(
    bool force_random, int key_index = 0) {
  static const absl::NoDestructor<RsaSsaPssParameters> parameters([]() {
    absl::StatusOr<RsaSsaPssParameters> parameters =
        RsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(3072)
            .SetPublicExponent(kF4)
            .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
            .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
            .SetSaltLengthInBytes(32)
            .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());

  if (force_random) {
    internal::RsaPrivateKey rsa_private_key;
    internal::RsaPublicKey rsa_public_key;
    absl::Status status =
        NewRsaKeyPairF4(3072, &rsa_private_key, &rsa_public_key);
    ABSL_CHECK_OK(status);
    absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
        *parameters, BigInteger(rsa_public_key.n),
        /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
    ABSL_CHECK_OK(public_key);
    absl::StatusOr<RsaSsaPssPrivateKey> private_key =
        RsaSsaPssPrivateKey::Builder()
            .SetPublicKey(*public_key)
            .SetPrimeP(RestrictedData(rsa_private_key.p,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedData(rsa_private_key.q,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(RestrictedData(rsa_private_key.dp,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(RestrictedData(rsa_private_key.dq,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrivateExponent(RestrictedData(rsa_private_key.d,
                                               InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(RestrictedData(rsa_private_key.crt,
                                              InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    ABSL_CHECK_OK(private_key);
    return std::make_unique<RsaSsaPssPrivateKey>(*private_key);
  }
  if (key_index == 0) {
    return CloneKeyOrDie<SignaturePrivateKey>(
        *Create3072BitTestVector().signature_private_key);
  } else if (key_index == 1) {
    return CloneKeyOrDie<SignaturePrivateKey>(
        *Create3072BitTestVector2().signature_private_key);
  }
  ABSL_LOG(FATAL) << "Could not find a 3072-bit RSA Pss key in test vectors";
  return nullptr;
}

std::unique_ptr<SignaturePrivateKey> GenerateRsaPss4096PrivateKeyOrDie(
    bool force_random, int key_index = 0) {
  static const absl::NoDestructor<RsaSsaPssParameters> parameters([]() {
    absl::StatusOr<RsaSsaPssParameters> parameters =
        RsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(4096)
            .SetPublicExponent(kF4)
            .SetSigHashType(RsaSsaPssParameters::HashType::kSha384)
            .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha384)
            .SetSaltLengthInBytes(48)
            .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());

  if (force_random) {
    internal::RsaPrivateKey rsa_private_key;
    internal::RsaPublicKey rsa_public_key;
    absl::Status status =
        NewRsaKeyPairF4(4096, &rsa_private_key, &rsa_public_key);
    ABSL_CHECK_OK(status);
    absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
        *parameters, BigInteger(rsa_public_key.n),
        /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
    ABSL_CHECK_OK(public_key);
    absl::StatusOr<RsaSsaPssPrivateKey> private_key =
        RsaSsaPssPrivateKey::Builder()
            .SetPublicKey(*public_key)
            .SetPrimeP(RestrictedData(rsa_private_key.p,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedData(rsa_private_key.q,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(RestrictedData(rsa_private_key.dp,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(RestrictedData(rsa_private_key.dq,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrivateExponent(RestrictedData(rsa_private_key.d,
                                               InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(RestrictedData(rsa_private_key.crt,
                                              InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    ABSL_CHECK_OK(private_key);
    return std::make_unique<RsaSsaPssPrivateKey>(*private_key);
  }
  if (key_index == 0) {
    return CloneKeyOrDie<SignaturePrivateKey>(
        *Create4096BitTestVector().signature_private_key);
  } else if (key_index == 1) {
    return CloneKeyOrDie<SignaturePrivateKey>(
        *Create4096BitTestVector2().signature_private_key);
  }
  ABSL_LOG(FATAL) << "Could not find a 4096-bit RSA Pss key in test vectors";
  return nullptr;
}

std::unique_ptr<SignaturePrivateKey> GenerateRsa3072Pkcs1PrivateKeyOrDie(
    bool force_random, int key_index = 0) {
  static const absl::NoDestructor<RsaSsaPkcs1Parameters> parameters([]() {
    absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
        RsaSsaPkcs1Parameters::Builder()
            .SetModulusSizeInBits(3072)
            .SetPublicExponent(kF4)
            .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
            .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());

  if (force_random) {
    internal::RsaPrivateKey rsa_private_key;
    internal::RsaPublicKey rsa_public_key;
    absl::Status status =
        NewRsaKeyPairF4(3072, &rsa_private_key, &rsa_public_key);
    ABSL_CHECK_OK(status);
    absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
        RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(rsa_public_key.n),
                                     /*id_requirement=*/absl::nullopt,
                                     GetPartialKeyAccess());
    ABSL_CHECK_OK(public_key);
    absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
        RsaSsaPkcs1PrivateKey::Builder()
            .SetPublicKey(*public_key)
            .SetPrimeP(RestrictedData(rsa_private_key.p,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedData(rsa_private_key.q,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(RestrictedData(rsa_private_key.dp,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(RestrictedData(rsa_private_key.dq,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrivateExponent(RestrictedData(rsa_private_key.d,
                                               InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(RestrictedData(rsa_private_key.crt,
                                              InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    return std::make_unique<RsaSsaPkcs1PrivateKey>(*private_key);
  }
  if (key_index == 0) {
    return CloneKeyOrDie<SignaturePrivateKey>(
        *Create3072BitsTestVector().signature_private_key);
  } else if (key_index == 1) {
    return CloneKeyOrDie<SignaturePrivateKey>(
        *CreateWycheproof3072BitsTestVector().signature_private_key);
  }
  ABSL_LOG(FATAL) << "Could not find a 3072-bit RSA Pkcs1 key in test vectors";
  return nullptr;
}

std::unique_ptr<SignaturePrivateKey> GenerateRsa4096Pkcs1PrivateKeyOrDie(
    bool force_random, int key_index = 0) {
  static const absl::NoDestructor<RsaSsaPkcs1Parameters> parameters([]() {
    absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
        RsaSsaPkcs1Parameters::Builder()
            .SetModulusSizeInBits(4096)
            .SetPublicExponent(kF4)
            .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha384)
            .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());

  if (force_random) {
    internal::RsaPrivateKey rsa_private_key;
    internal::RsaPublicKey rsa_public_key;
    absl::Status status =
        NewRsaKeyPairF4(4096, &rsa_private_key, &rsa_public_key);
    ABSL_CHECK_OK(status);
    absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
        RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(rsa_public_key.n),
                                     /*id_requirement=*/absl::nullopt,
                                     GetPartialKeyAccess());
    ABSL_CHECK_OK(public_key);
    absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
        RsaSsaPkcs1PrivateKey::Builder()
            .SetPublicKey(*public_key)
            .SetPrimeP(RestrictedData(rsa_private_key.p,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedData(rsa_private_key.q,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(RestrictedData(rsa_private_key.dp,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(RestrictedData(rsa_private_key.dq,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrivateExponent(RestrictedData(rsa_private_key.d,
                                               InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(RestrictedData(rsa_private_key.crt,
                                              InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    return std::make_unique<RsaSsaPkcs1PrivateKey>(*private_key);
  }
  if (key_index == 0) {
    return CloneKeyOrDie<SignaturePrivateKey>(
        *Create4096BitsTestVector().signature_private_key);
  } else if (key_index == 1) {
    return CloneKeyOrDie<SignaturePrivateKey>(
        *Create4096BitsTestVector2().signature_private_key);
  }
  ABSL_LOG(FATAL) << "Could not find a 4096-bit RSA Pkcs1 key in test vectors";
  return nullptr;
}

}  // namespace

MlDsaPrivateKey GenerateMlDsaPrivateKeyForTestOrDie(
    CompositeMlDsaParameters::MlDsaInstance instance) {
  switch (instance) {
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa65: {
      std::string public_key_bytes;
      public_key_bytes.resize(MLDSA65_PUBLIC_KEY_BYTES);
      internal::SecretBuffer private_seed_bytes(MLDSA_SEED_BYTES);
      auto bssl_private_key = util::MakeSecretUniquePtr<MLDSA65_private_key>();
      ABSL_CHECK_EQ(1, MLDSA65_generate_key(
                           reinterpret_cast<uint8_t*>(public_key_bytes.data()),
                           private_seed_bytes.data(), bssl_private_key.get()));
      absl::StatusOr<MlDsaParameters> parameters =
          MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                                  MlDsaParameters::Variant::kNoPrefix);
      ABSL_CHECK_OK(parameters);
      absl::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
          *parameters, public_key_bytes, /*id_requirement=*/absl::nullopt,
          GetPartialKeyAccess());
      ABSL_CHECK_OK(public_key);
      absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
          *public_key,
          RestrictedData(
              util::internal::AsSecretData(std::move(private_seed_bytes)),
              InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
      ABSL_CHECK_OK(private_key);
      return *private_key;
    }
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa87: {
      std::string public_key_bytes;
      public_key_bytes.resize(MLDSA87_PUBLIC_KEY_BYTES);
      internal::SecretBuffer private_seed_bytes(MLDSA_SEED_BYTES);
      auto bssl_private_key = util::MakeSecretUniquePtr<MLDSA87_private_key>();
      ABSL_CHECK_EQ(1, MLDSA87_generate_key(
                           reinterpret_cast<uint8_t*>(public_key_bytes.data()),
                           private_seed_bytes.data(), bssl_private_key.get()));
      absl::StatusOr<MlDsaParameters> parameters =
          MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa87,
                                  MlDsaParameters::Variant::kNoPrefix);
      ABSL_CHECK_OK(parameters);
      absl::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
          *parameters, public_key_bytes, /*id_requirement=*/absl::nullopt,
          GetPartialKeyAccess());
      ABSL_CHECK_OK(public_key);
      absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
          *public_key,
          RestrictedData(
              util::internal::AsSecretData(std::move(private_seed_bytes)),
              InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
      ABSL_CHECK_OK(private_key);
      return *private_key;
    }
    default:
      ABSL_LOG(FATAL) << "Unsupported ML-DSA instance";
  }
}

std::unique_ptr<SignaturePrivateKey> GenerateClassicalPrivateKeyForTestOrDie(
    CompositeMlDsaParameters::ClassicalAlgorithm algorithm, bool force_random,
    int key_index) {
  switch (algorithm) {
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519:
      return GenerateEd25519PrivateKeyOrDie();
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256:
      return GenerateEcdsaPrivateKeyOrDie(subtle::EllipticCurveType::NIST_P256,
                                          EcdsaParameters::CurveType::kNistP256,
                                          EcdsaParameters::HashType::kSha256);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384:
      return GenerateEcdsaPrivateKeyOrDie(subtle::EllipticCurveType::NIST_P384,
                                          EcdsaParameters::CurveType::kNistP384,
                                          EcdsaParameters::HashType::kSha384);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521:
      return GenerateEcdsaPrivateKeyOrDie(subtle::EllipticCurveType::NIST_P521,
                                          EcdsaParameters::CurveType::kNistP521,
                                          EcdsaParameters::HashType::kSha512);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss:
      return GenerateRsaPss3072PrivateKeyOrDie(force_random, key_index);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss:
      return GenerateRsaPss4096PrivateKeyOrDie(force_random, key_index);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1:
      return GenerateRsa3072Pkcs1PrivateKeyOrDie(force_random, key_index);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1:
      return GenerateRsa4096Pkcs1PrivateKeyOrDie(force_random, key_index);
    default:
      ABSL_LOG(FATAL) << "Unsupported classical algorithm";
  }
}

CompositeMlDsaPrivateKey GenerateCompositeMlDsaPrivateKeyForTestOrDie(
    const CompositeMlDsaParameters& parameters, bool force_random,
    std::optional<int> id_requirement, int key_index) {
  MlDsaPrivateKey ml_dsa_private_key =
      GenerateMlDsaPrivateKeyForTestOrDie(parameters.GetMlDsaInstance());
  std::unique_ptr<SignaturePrivateKey> classical_private_key =
      GenerateClassicalPrivateKeyForTestOrDie(
          parameters.GetClassicalAlgorithm(), force_random, key_index);
  absl::StatusOr<CompositeMlDsaPrivateKey> private_key =
      CompositeMlDsaPrivateKey::Create(parameters, ml_dsa_private_key,
                                       std::move(classical_private_key),
                                       id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return *private_key;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
