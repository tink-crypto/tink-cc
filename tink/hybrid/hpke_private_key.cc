// Copyright 2023 Google LLC
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

#include "tink/hybrid/hpke_private_key.h"

#include <memory>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/xwing_util.h"
#include "tink/secret_data.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#else
#include "openssl/ec.h"
#endif
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace {

absl::StatusOr<subtle::EllipticCurveType> CurveTypeFromKemId(
    HpkeParameters::KemId kem_id) {
  switch (kem_id) {
    case HpkeParameters::KemId::kDhkemP256HkdfSha256:
      return subtle::EllipticCurveType::NIST_P256;
    case HpkeParameters::KemId::kDhkemP384HkdfSha384:
      return subtle::EllipticCurveType::NIST_P384;
    case HpkeParameters::KemId::kDhkemP521HkdfSha512:
      return subtle::EllipticCurveType::NIST_P521;
    case HpkeParameters::KemId::kDhkemX25519HkdfSha256:
      return subtle::EllipticCurveType::CURVE25519;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unknown KEM ID: ", kem_id));
  }
}

absl::Status ValidatePrivateKeyLength(HpkeParameters::KemId kem_id,
                                      int length) {
  int expected_length;
  switch (kem_id) {
    // Key lengths from 'Nsk' column in
    // https://www.rfc-editor.org/rfc/rfc9180.html#table-2.
    case HpkeParameters::KemId::kDhkemP256HkdfSha256:
      expected_length = 32;
      break;
    case HpkeParameters::KemId::kDhkemP384HkdfSha384:
      expected_length = 48;
      break;
    case HpkeParameters::KemId::kDhkemP521HkdfSha512:
      expected_length = 66;
      break;
    case HpkeParameters::KemId::kDhkemX25519HkdfSha256:
      expected_length = 32;
      break;
    // Key length from
    // https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-09.html#name-encoding-and-sizes
    case HpkeParameters::KemId::kXWing:
      expected_length = 32;
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unknown KEM ID: ", kem_id));
  }

  // Validate key length.
  if (expected_length != length) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat(
            "Invalid private key length for KEM %d (expected %d, got %d)",
            kem_id, expected_length, length));
  }

  return absl::OkStatus();
}

bool IsNistKem(HpkeParameters::KemId kem_id) {
  return kem_id == HpkeParameters::KemId::kDhkemP256HkdfSha256 ||
         kem_id == HpkeParameters::KemId::kDhkemP384HkdfSha384 ||
         kem_id == HpkeParameters::KemId::kDhkemP521HkdfSha512;
}

absl::Status ValidateNistEcKeyPair(subtle::EllipticCurveType curve,
                                   absl::string_view public_key_bytes,
                                   const SecretData& private_key_bytes) {
  // Construct EC_KEY from public and private key bytes.
  absl::StatusOr<internal::SslUniquePtr<EC_GROUP>> group =
      internal::EcGroupFromCurveType(curve);
  if (!group.ok()) {
    return group.status();
  }
  internal::SslUniquePtr<EC_KEY> key(EC_KEY_new());
  EC_KEY_set_group(key.get(), group->get());

  absl::StatusOr<internal::SslUniquePtr<EC_POINT>> public_key =
      internal::EcPointDecode(curve, subtle::EcPointFormat::UNCOMPRESSED,
                              public_key_bytes);
  if (!public_key.ok()) {
    return public_key.status();
  }

  if (!EC_KEY_set_public_key(key.get(), public_key->get())) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid public key: ", internal::GetSslErrors()));
  }

  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> priv_key =
      internal::SecretDataToBignum(private_key_bytes);
  if (!priv_key.ok()) {
    return priv_key.status();
  }
  int ec_key_set_private_key_result = internal::CallWithCoreDumpProtection(
      [&] { return EC_KEY_set_private_key(key.get(), priv_key->get()); });
  if (!ec_key_set_private_key_result) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid private key: ", internal::GetSslErrors()));
  }

  // Check that EC_KEY is valid.
  int ec_key_check_key_result = internal::CallWithCoreDumpProtection(
      [&] { return EC_KEY_check_key(key.get()); });
  if (!ec_key_check_key_result) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid EC key pair: ", internal::GetSslErrors()));
  }

  return absl::OkStatus();
}

bool IsX25519Kem(HpkeParameters::KemId kem_id) {
  return kem_id == HpkeParameters::KemId::kDhkemX25519HkdfSha256;
}

absl::Status ValidateX25519KeyPair(absl::string_view public_key_bytes,
                                   const SecretData& private_key_bytes) {
  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::X25519KeyFromPrivateKey(private_key_bytes);
  if (!x25519_key.ok()) {
    return x25519_key.status();
  }
  auto public_key_bytes_from_private = absl::string_view(
      reinterpret_cast<const char*>((*x25519_key)->public_value),
      internal::X25519KeyPubKeySize());
  if (public_key_bytes != public_key_bytes_from_private) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "X25519 private key does not match the specified X25519 public key.");
  }
  return absl::OkStatus();
}

absl::Status ValidateXWingKeyPair(absl::string_view public_key_bytes,
                                  const SecretData& private_key_bytes) {
  absl::StatusOr<internal::XWingKey> xwing_key =
      internal::XWingKeyFromPrivateKey(private_key_bytes);
  if (!xwing_key.ok()) {
    return xwing_key.status();
  }
  auto public_key_bytes_from_private = absl::string_view(
      reinterpret_cast<const char*>(xwing_key->public_key.data()),
      xwing_key->public_key.size());
  if (public_key_bytes != public_key_bytes_from_private) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "XWing private key does not match the specified XWing public key.");
  }
  return absl::OkStatus();
}

absl::Status ValidateKeyPair(const HpkePublicKey& public_key,
                             const RestrictedData& private_key_bytes,
                             PartialKeyAccessToken token) {
  HpkeParameters::KemId kem_id = public_key.GetParameters().GetKemId();
  absl::string_view public_key_bytes = public_key.GetPublicKeyBytes(token);
  const SecretData& secret =
      private_key_bytes.Get(InsecureSecretKeyAccess::Get());

  if (IsNistKem(kem_id)) {
    absl::StatusOr<subtle::EllipticCurveType> curve =
        CurveTypeFromKemId(kem_id);
    if (!curve.ok()) {
      return curve.status();
    }
    return ValidateNistEcKeyPair(*curve, public_key_bytes, secret);
  } else if (IsX25519Kem(kem_id)) {
    return ValidateX25519KeyPair(public_key_bytes, secret);
  }
  return ValidateXWingKeyPair(public_key_bytes, secret);
}

}  // namespace

absl::StatusOr<HpkePrivateKey> HpkePrivateKey::Create(
    const HpkePublicKey& public_key, const RestrictedData& private_key_bytes,
    PartialKeyAccessToken token) {
  absl::Status key_length_validation = ValidatePrivateKeyLength(
      public_key.GetParameters().GetKemId(), private_key_bytes.size());
  if (!key_length_validation.ok()) {
    return key_length_validation;
  }
  absl::Status key_pair_validation =
      ValidateKeyPair(public_key, private_key_bytes, token);
  if (!key_pair_validation.ok()) {
    return key_pair_validation;
  }
  return HpkePrivateKey(public_key, private_key_bytes);
}

bool HpkePrivateKey::operator==(const Key& other) const {
  const HpkePrivateKey* that = dynamic_cast<const HpkePrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (public_key_ != that->public_key_) {
    return false;
  }
  return private_key_bytes_ == that->private_key_bytes_;
}

}  // namespace tink
}  // namespace crypto
