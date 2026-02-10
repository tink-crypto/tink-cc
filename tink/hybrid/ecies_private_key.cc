// Copyright 2024 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/hybrid/ecies_private_key.h"

#include <cstddef>
#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#else
#include "openssl/ec.h"
#endif
#include "tink/ec_point.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace {

absl::StatusOr<subtle::EllipticCurveType> SubtleCurveType(
    EciesParameters::CurveType curve_type) {
  switch (curve_type) {
    case EciesParameters::CurveType::kNistP256:
      return subtle::EllipticCurveType::NIST_P256;
    case EciesParameters::CurveType::kNistP384:
      return subtle::EllipticCurveType::NIST_P384;
    case EciesParameters::CurveType::kNistP521:
      return subtle::EllipticCurveType::NIST_P521;
    case EciesParameters::CurveType::kX25519:
      return subtle::EllipticCurveType::CURVE25519;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unknown curve type: ", curve_type));
  }
}

absl::Status ValidateNistKeyPair(const EciesPublicKey& public_key,
                                 const RestrictedData& private_key_value,
                                 PartialKeyAccessToken token) {
  internal::SslUniquePtr<EC_KEY> key(EC_KEY_new());

  // Set EC_KEY group.
  absl::StatusOr<subtle::EllipticCurveType> curve =
      SubtleCurveType(public_key.GetParameters().GetCurveType());
  if (!curve.ok()) {
    return curve.status();
  }
  absl::StatusOr<internal::SslUniquePtr<EC_GROUP>> group =
      internal::EcGroupFromCurveType(*curve);
  if (!group.ok()) {
    return group.status();
  }
  EC_KEY_set_group(key.get(), group->get());

  // Set EC_KEY public key.
  absl::optional<EcPoint> ec_point = public_key.GetNistCurvePoint(token);
  if (!ec_point.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Missing public point for NIST curve public key.");
  }
  absl::StatusOr<internal::SslUniquePtr<EC_POINT>> public_point =
      internal::GetEcPoint(*curve, ec_point->GetX().GetValue(),
                           ec_point->GetY().GetValue());
  if (!public_point.ok()) {
    return public_point.status();
  }
  if (!EC_KEY_set_public_key(key.get(), public_point->get())) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid public key: ", internal::GetSslErrors()));
  }

  // Set EC_KEY private key.
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> priv_big_num =
      internal::StringToBignum(
          private_key_value.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!priv_big_num.ok()) {
    return priv_big_num.status();
  }
  int ec_key_set_private_key_result = internal::CallWithCoreDumpProtection(
      [&]() { return EC_KEY_set_private_key(key.get(), priv_big_num->get()); });
  if (!ec_key_set_private_key_result) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid private key: ", internal::GetSslErrors()));
  }

  // Check that EC_KEY is valid.
  int ec_key_check_key_result = internal::CallWithCoreDumpProtection(
      [&]() { return EC_KEY_check_key(key.get()); });
  if (!ec_key_check_key_result) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid EC key pair: ", internal::GetSslErrors()));
  }

  return absl::OkStatus();
}

absl::Status ValidateX25519KeyPair(const EciesPublicKey& public_key,
                                   const RestrictedData& private_key_bytes,
                                   PartialKeyAccessToken token) {
  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::X25519KeyFromPrivateKey(
          private_key_bytes.Get(InsecureSecretKeyAccess::Get()));
  if (!x25519_key.ok()) {
    return x25519_key.status();
  }

  absl::optional<absl::string_view> public_key_bytes =
      public_key.GetX25519CurvePointBytes(token);
  if (!public_key_bytes.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Missing public key bytes for X25519 public key.");
  }

  absl::string_view public_key_bytes_from_private = absl::string_view(
      reinterpret_cast<const char*>((*x25519_key)->public_value),
      internal::X25519KeyPubKeySize());

  if (public_key_bytes != public_key_bytes_from_private) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "X25519 private key does not match the specified X25519 public key.");
  }

  return absl::OkStatus();
}

}  // namespace

absl::StatusOr<EciesPrivateKey> EciesPrivateKey::CreateForNistCurve(
    const EciesPublicKey& public_key, const RestrictedData& private_key_value,
    PartialKeyAccessToken token) {
  size_t key_length = public_key.GetParameters().GetPrivateKeyLength();
  if (private_key_value.size() !=
      public_key.GetParameters().GetPrivateKeyLength()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Private key length ", private_key_value.size(),
                     " is different from expected length ", key_length));
  }

  // Validate that public and private key match.
  absl::Status key_pair_validation =
      ValidateNistKeyPair(public_key, private_key_value, token);
  if (!key_pair_validation.ok()) {
    return key_pair_validation;
  }
  return EciesPrivateKey(public_key, private_key_value);
}

absl::StatusOr<EciesPrivateKey> EciesPrivateKey::CreateForNistCurve(
    const EciesPublicKey& public_key,
    const RestrictedBigInteger& private_key_value,
    PartialKeyAccessToken token) {
  absl::StatusOr<RestrictedData> adjusted_private_key =
      private_key_value.EncodeWithFixedSize(
          public_key.GetParameters().GetPrivateKeyLength());
  if (!adjusted_private_key.ok()) {
    return adjusted_private_key.status();
  }

  return EciesPrivateKey::CreateForNistCurve(public_key, *adjusted_private_key,
                                             token);
}

absl::StatusOr<EciesPrivateKey>
EciesPrivateKey::CreateForNistCurveAllowNonConstantTime(
    const EciesPublicKey& public_key, const RestrictedData& private_key_value,
    PartialKeyAccessToken token) {
  absl::StatusOr<SecretData> adjusted_private_key =
      internal::ParseBigIntToFixedLength(
          private_key_value.GetSecret(InsecureSecretKeyAccess::Get()),
          public_key.GetParameters().GetPrivateKeyLength());

  if (!adjusted_private_key.ok()) {
    return adjusted_private_key.status();
  }

  return CreateForNistCurve(public_key,
                            RestrictedData(std::move(*adjusted_private_key),
                                           InsecureSecretKeyAccess::Get()),
                            token);
}

absl::optional<RestrictedBigInteger> EciesPrivateKey::GetNistPrivateKeyValue(
    PartialKeyAccessToken token) const {
  absl::MutexLock lock(mutex_);
  switch (public_key_.GetParameters().GetCurveType()) {
    case EciesParameters::CurveType::kNistP256:
    case EciesParameters::CurveType::kNistP384:
    case EciesParameters::CurveType::kNistP521:
      if (!private_key_value_big_integer_.has_value()) {
        private_key_value_big_integer_.emplace(
            private_key_bytes_.value().GetSecret(
                InsecureSecretKeyAccess::Get()),
            InsecureSecretKeyAccess::Get());
      }
      return *private_key_value_big_integer_;
    default:
      return absl::nullopt;
  }
}

absl::StatusOr<EciesPrivateKey> EciesPrivateKey::CreateForCurveX25519(
    const EciesPublicKey& public_key, const RestrictedData& private_key_bytes,
    PartialKeyAccessToken token) {
  // Validate private key length.
  int private_key_length =
      private_key_bytes.GetSecret(InsecureSecretKeyAccess::Get()).length();
  if (private_key_length != internal::X25519KeyPrivKeySize()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat(
            "Invalid X25519 private key length (expected %d, got %d)",
            internal::X25519KeyPrivKeySize(), private_key_length));
  }

  // Validate that public and private key match.
  absl::Status key_pair_validation =
      ValidateX25519KeyPair(public_key, private_key_bytes, token);
  if (!key_pair_validation.ok()) {
    return key_pair_validation;
  }

  return EciesPrivateKey(public_key, private_key_bytes);
}

bool EciesPrivateKey::operator==(const Key& other) const {
  const EciesPrivateKey* that = dynamic_cast<const EciesPrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (public_key_ != that->public_key_) {
    return false;
  }
  if (private_key_bytes_ != that->private_key_bytes_) {
    return false;
  }
  return private_key_bytes_ == that->private_key_bytes_;
}

}  // namespace tink
}  // namespace crypto
