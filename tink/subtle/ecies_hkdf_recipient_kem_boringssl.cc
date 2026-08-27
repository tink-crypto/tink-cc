// Copyright 2017 Google Inc.
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
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/subtle/ecies_hkdf_recipient_kem_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/secret_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {

class EciesHkdfNistPCurveRecipientKemBoringSslImpl
    : public EciesHkdfRecipientKemBoringSsl {
 public:
  EciesHkdfNistPCurveRecipientKemBoringSslImpl(
      EllipticCurveType curve, SecretData priv_key_value,
      internal::SslUniquePtr<EC_GROUP> ec_group)
      : curve_(curve),
        priv_key_value_(std::move(priv_key_value)),
        ec_group_(std::move(ec_group)) {}

  absl::StatusOr<SecretData> GenerateKey(
      absl::string_view kem_bytes, HashType hash, absl::string_view hkdf_salt,
      absl::string_view hkdf_info, uint32_t key_size_in_bytes,
      EcPointFormat point_format) const override;

 private:
  EllipticCurveType curve_;
  SecretData priv_key_value_;
  internal::SslUniquePtr<EC_GROUP> ec_group_;
};

absl::StatusOr<SecretData>
EciesHkdfNistPCurveRecipientKemBoringSslImpl::GenerateKey(
    absl::string_view kem_bytes, HashType hash, absl::string_view hkdf_salt,
    absl::string_view hkdf_info, uint32_t key_size_in_bytes,
    EcPointFormat point_format) const {
  auto status_or_ec_point =
      internal::EcPointDecode(curve_, point_format, kem_bytes);
  if (!status_or_ec_point.ok()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Invalid KEM bytes: ", status_or_ec_point.status().message()));
  }
  internal::SslUniquePtr<EC_POINT> pub_key =
      std::move(status_or_ec_point.value());
  internal::SslUniquePtr<BIGNUM> priv_key =
      internal::CallWithCoreDumpProtection([&]() {
        return internal::SslUniquePtr<BIGNUM>(
            BN_bin2bn(priv_key_value_.data(), priv_key_value_.size(), nullptr));
      });
  ABSL_ASSIGN_OR_RETURN(
      SecretData shared_secret,
      internal::ComputeEcdhSharedSecret(curve_, priv_key.get(), pub_key.get()));
  return Hkdf::ComputeEciesHkdfSymmetricKey(
      hash, kem_bytes, shared_secret, hkdf_salt, hkdf_info, key_size_in_bytes);
}

class EciesHkdfX25519RecipientKemBoringSslImpl
    : public EciesHkdfRecipientKemBoringSsl {
 public:
  explicit EciesHkdfX25519RecipientKemBoringSslImpl(
      internal::SslUniquePtr<EVP_PKEY> private_key)
      : private_key_(std::move(private_key)) {}

  absl::StatusOr<SecretData> GenerateKey(
      absl::string_view kem_bytes, HashType hash, absl::string_view hkdf_salt,
      absl::string_view hkdf_info, uint32_t key_size_in_bytes,
      EcPointFormat point_format) const override;

 private:
  const internal::SslUniquePtr<EVP_PKEY> private_key_;
};

absl::StatusOr<SecretData>
EciesHkdfX25519RecipientKemBoringSslImpl::GenerateKey(
    absl::string_view kem_bytes, HashType hash, absl::string_view hkdf_salt,
    absl::string_view hkdf_info, uint32_t key_size_in_bytes,
    EcPointFormat point_format) const {
  if (point_format != EcPointFormat::COMPRESSED) {
    return absl::InvalidArgumentError(
        "X25519 only supports compressed elliptic curve points");
  }

  if (kem_bytes.size() !=
      static_cast<size_t>(internal::X25519KeyPubKeySize())) {
    return absl::InvalidArgumentError("kem_bytes has unexpected size");
  }

  internal::SslUniquePtr<EVP_PKEY> peer_key(EVP_PKEY_new_raw_public_key(
      /*type=*/EVP_PKEY_X25519, /*unused=*/nullptr,
      /*in=*/reinterpret_cast<const uint8_t*>(kem_bytes.data()),
      /*len=*/internal::Ed25519KeyPubKeySize()));
  if (peer_key == nullptr) {
    return absl::InternalError("EVP_PKEY_new_raw_public_key failed");
  }

  ABSL_ASSIGN_OR_RETURN(
      SecretData shared_secret,
      internal::ComputeX25519SharedSecret(private_key_.get(), peer_key.get()));

  return Hkdf::ComputeEciesHkdfSymmetricKey(
      hash, kem_bytes, shared_secret, hkdf_salt, hkdf_info, key_size_in_bytes);
}

}  // namespace

// static
absl::StatusOr<std::unique_ptr<EciesHkdfRecipientKemBoringSsl>>
EciesHkdfRecipientKemBoringSsl::New(EllipticCurveType curve,
                                    SecretData priv_key) {
  switch (curve) {
    case EllipticCurveType::NIST_P256:
    case EllipticCurveType::NIST_P384:
    case EllipticCurveType::NIST_P521:
      return EciesHkdfNistPCurveRecipientKemBoringSsl::New(curve,
                                                           std::move(priv_key));
    case EllipticCurveType::CURVE25519:
      return EciesHkdfX25519RecipientKemBoringSsl::New(curve,
                                                       std::move(priv_key));
    default:
      return absl::Status(absl::StatusCode::kUnimplemented,
                          "Unsupported elliptic curve");
  }
}

// static
absl::StatusOr<std::unique_ptr<EciesHkdfRecipientKemBoringSsl>>
EciesHkdfNistPCurveRecipientKemBoringSsl::New(EllipticCurveType curve,
                                              SecretData priv_key) {
  ABSL_RETURN_IF_ERROR(internal::CheckFipsCompatibility<
                       EciesHkdfNistPCurveRecipientKemBoringSsl>());

  if (priv_key.empty()) {
    return absl::InvalidArgumentError("empty priv_key");
  }
  ABSL_ASSIGN_OR_RETURN(internal::SslUniquePtr<EC_GROUP> ec_group,
                        internal::EcGroupFromCurveType(curve));
  return std::make_unique<EciesHkdfNistPCurveRecipientKemBoringSslImpl>(
      curve, std::move(priv_key), std::move(ec_group));
}

// static
absl::StatusOr<std::unique_ptr<EciesHkdfRecipientKemBoringSsl>>
EciesHkdfX25519RecipientKemBoringSsl::New(EllipticCurveType curve,
                                          SecretData priv_key) {
  ABSL_RETURN_IF_ERROR(
      internal::CheckFipsCompatibility<EciesHkdfX25519RecipientKemBoringSsl>());

  if (curve != CURVE25519) {
    return absl::InvalidArgumentError("curve is not CURVE25519");
  }
  if (priv_key.size() != static_cast<size_t>(internal::X25519KeyPubKeySize())) {
    return absl::InvalidArgumentError("pubx has unexpected length");
  }

  internal::SslUniquePtr<EVP_PKEY> ssl_priv_key(
      internal::CallWithCoreDumpProtection([&] {
        return EVP_PKEY_new_raw_private_key(
            /*type=*/EVP_PKEY_X25519, /*unused=*/nullptr,
            /*in=*/priv_key.data(),
            /*len=*/internal::Ed25519KeyPrivKeySize());
      }));
  if (ssl_priv_key == nullptr) {
    return absl::InternalError("EVP_PKEY_new_raw_private_key failed");
  }

  return std::make_unique<EciesHkdfX25519RecipientKemBoringSslImpl>(
      std::move(ssl_priv_key));
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
