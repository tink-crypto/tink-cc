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

#include "tink/jwt/jwt_ecdsa_public_key.h"

#include <string>
#include <utility>

#include "absl/base/internal/endian.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#else
#include "openssl/ec.h"
#endif
#include "tink/ec_point.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

util::Status ValidatePublicPoint(JwtEcdsaParameters::Algorithm algorithm,
                                 const EcPoint& point) {
  subtle::EllipticCurveType curve;
  switch (algorithm) {
    case JwtEcdsaParameters::Algorithm::kEs256:
      curve = subtle::EllipticCurveType::NIST_P256;
      break;
    case JwtEcdsaParameters::Algorithm::kEs384:
      curve = subtle::EllipticCurveType::NIST_P384;
      break;
    case JwtEcdsaParameters::Algorithm::kEs512:
      curve = subtle::EllipticCurveType::NIST_P521;
      break;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unknown algorithm: ", algorithm));
  }
  // Internally calls EC_POINT_set_affine_coordinates_GFp, which, in BoringSSL
  // and OpenSSL versions > 1.1.0, already checks if the point is on the curve.
  absl::StatusOr<internal::SslUniquePtr<EC_POINT>> ec_point =
      internal::GetEcPoint(curve, point.GetX().GetValue(),
                           point.GetY().GetValue());
  if (!ec_point.ok()) {
    return ec_point.status();
  }

  absl::StatusOr<internal::SslUniquePtr<EC_GROUP>> group =
      internal::EcGroupFromCurveType(curve);
  if (!group.ok()) {
    return group.status();
  }
  if (EC_POINT_is_on_curve(group->get(), ec_point->get(), /*ctx=*/nullptr) !=
      1) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("EC public point is not on curve ",
                                     subtle::EnumToString(curve)));
  }
  return util::OkStatus();
}

}  // namespace

JwtEcdsaPublicKey::Builder& JwtEcdsaPublicKey::Builder::SetParameters(
    const JwtEcdsaParameters& parameters) {
  parameters_ = parameters;
  return *this;
}

JwtEcdsaPublicKey::Builder& JwtEcdsaPublicKey::Builder::SetPublicPoint(
    const EcPoint& public_point) {
  public_point_ = public_point;
  return *this;
}

JwtEcdsaPublicKey::Builder& JwtEcdsaPublicKey::Builder::SetIdRequirement(
    int id_requirement) {
  id_requirement_ = id_requirement;
  return *this;
}

JwtEcdsaPublicKey::Builder& JwtEcdsaPublicKey::Builder::SetCustomKid(
    absl::string_view custom_kid) {
  custom_kid_ = custom_kid.data();
  return *this;
}

absl::StatusOr<absl::optional<std::string>>
JwtEcdsaPublicKey::Builder::ComputeKid() {
  if (parameters_->GetKidStrategy() ==
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId) {
    if (custom_kid_.has_value()) {
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Custom kid must not be set for KidStrategy::kBase64EncodedKeyId.");
    }
    std::string base64_kid;
    char buffer[4];
    absl::big_endian::Store32(buffer, *id_requirement_);
    absl::WebSafeBase64Escape(absl::string_view(buffer, 4), &base64_kid);
    return base64_kid;
  }
  if (parameters_->GetKidStrategy() ==
      JwtEcdsaParameters::KidStrategy::kCustom) {
    if (!custom_kid_.has_value()) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Custom kid must be set for KidStrategy::kCustom.");
    }
    return custom_kid_;
  }
  if (parameters_->GetKidStrategy() ==
      JwtEcdsaParameters::KidStrategy::kIgnored) {
    if (custom_kid_.has_value()) {
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Custom kid must not be set for KidStrategy::kIgnored.");
    }
    return absl::nullopt;
  }
  return util::Status(absl::StatusCode::kInvalidArgument,
                      "Unknown kid strategy.");
}

absl::StatusOr<JwtEcdsaPublicKey> JwtEcdsaPublicKey::Builder::Build(
    PartialKeyAccessToken token) {
  if (!parameters_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "JWT ECDSA parameters must be specified.");
  }
  if (!public_point_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "JWT ECDSA public point must be specified.");
  }
  util::Status point_validation =
      ValidatePublicPoint(parameters_->GetAlgorithm(), *public_point_);
  if (!point_validation.ok()) {
    return point_validation;
  }
  if (parameters_->HasIdRequirement() && !id_requirement_.has_value()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key without ID requirement with parameters with ID "
        "requirement");
  }
  if (!parameters_->HasIdRequirement() && id_requirement_.has_value()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key with ID requirement with parameters without ID "
        "requirement");
  }
  absl::StatusOr<absl::optional<std::string>> kid = ComputeKid();
  if (!kid.ok()) {
    return kid.status();
  }
  return JwtEcdsaPublicKey(*parameters_, *public_point_, id_requirement_,
                           std::move(*kid));
}

bool JwtEcdsaPublicKey::operator==(const Key& other) const {
  const JwtEcdsaPublicKey* that =
      dynamic_cast<const JwtEcdsaPublicKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (parameters_ != that->parameters_) {
    return false;
  }
  if (public_point_ != that->public_point_) {
    return false;
  }
  if (id_requirement_ != that->id_requirement_) {
    return false;
  }
  if (kid_ != that->kid_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
