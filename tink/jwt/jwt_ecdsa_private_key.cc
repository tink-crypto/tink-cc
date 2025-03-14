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

#include "tink/jwt/jwt_ecdsa_private_key.h"

#include <memory>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "tink/internal/call_with_core_dump_protection.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#else
#include "openssl/ec.h"
#endif
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_big_integer.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace {

absl::StatusOr<subtle::EllipticCurveType> SubtleCurveType(
    JwtEcdsaParameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtEcdsaParameters::Algorithm::kEs256:
      return subtle::EllipticCurveType::NIST_P256;
    case JwtEcdsaParameters::Algorithm::kEs384:
      return subtle::EllipticCurveType::NIST_P384;
    case JwtEcdsaParameters::Algorithm::kEs512:
      return subtle::EllipticCurveType::NIST_P521;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unknown curve type: ", algorithm));
  }
}

absl::Status ValidateKeyPair(const JwtEcdsaPublicKey& public_key,
                             const RestrictedBigInteger& private_key_value,
                             PartialKeyAccessToken token) {
  internal::SslUniquePtr<EC_KEY> key(EC_KEY_new());

  absl::StatusOr<subtle::EllipticCurveType> curve =
      SubtleCurveType(public_key.GetParameters().GetAlgorithm());
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
  const EcPoint& ec_point = public_key.GetPublicPoint(token);
  absl::StatusOr<internal::SslUniquePtr<EC_POINT>> public_point =
      internal::GetEcPoint(*curve, ec_point.GetX().GetValue(),
                           ec_point.GetY().GetValue());
  if (!public_point.ok()) {
    return public_point.status();
  }
  if (!EC_KEY_set_public_key(key.get(), public_point->get())) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid public key: ", internal::GetSslErrors()));
  }

  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> priv_big_num =
      internal::StringToBignum(
          private_key_value.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!priv_big_num.ok()) {
    return priv_big_num.status();
  }
  if (int set_private_key_res = internal::CallWithCoreDumpProtection([&]() {
        return EC_KEY_set_private_key(key.get(), priv_big_num->get());
      });
      !set_private_key_res) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid private key: ", internal::GetSslErrors()));
  }

  if (int validate_key_res = internal::CallWithCoreDumpProtection(
          [&]() { return EC_KEY_check_key(key.get()); });
      !validate_key_res) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid EC key pair: ", internal::GetSslErrors()));
  }
  return absl::OkStatus();
}

}  // namespace

absl::StatusOr<JwtEcdsaPrivateKey> JwtEcdsaPrivateKey::Create(
    const JwtEcdsaPublicKey& public_key,
    const RestrictedBigInteger& private_key_value,
    PartialKeyAccessToken token) {
  // Validate that the public and private key match.
  absl::Status key_pair_validation =
      ValidateKeyPair(public_key, private_key_value, token);
  if (!key_pair_validation.ok()) {
    return key_pair_validation;
  }

  return JwtEcdsaPrivateKey(public_key, private_key_value);
}

bool JwtEcdsaPrivateKey::operator==(const Key& other) const {
  const JwtEcdsaPrivateKey* that =
      dynamic_cast<const JwtEcdsaPrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (public_key_ != that->public_key_) {
    return false;
  }
  if (private_key_value_ != that->private_key_value_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
