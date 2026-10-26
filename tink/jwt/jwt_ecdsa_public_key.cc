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

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/ec_point.h"
#include "tink/internal/endian.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_public_key.h"

namespace crypto {
namespace tink {
namespace {

absl::StatusOr<EcdsaPublicKey> ToEcdsaPublicKey(
    const JwtEcdsaParameters& parameters, const EcPoint& public_point,
    PartialKeyAccessToken token) {
  EcdsaParameters::CurveType curve_type;
  EcdsaParameters::HashType hash_type;
  switch (parameters.GetAlgorithm()) {
    case JwtEcdsaParameters::Algorithm::kEs256:
      curve_type = EcdsaParameters::CurveType::kNistP256;
      hash_type = EcdsaParameters::HashType::kSha256;
      break;
    case JwtEcdsaParameters::Algorithm::kEs384:
      curve_type = EcdsaParameters::CurveType::kNistP384;
      hash_type = EcdsaParameters::HashType::kSha384;
      break;
    case JwtEcdsaParameters::Algorithm::kEs512:
      curve_type = EcdsaParameters::CurveType::kNistP521;
      hash_type = EcdsaParameters::HashType::kSha512;
      break;
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unknown algorithm: ", parameters.GetAlgorithm()));
  }
  ABSL_ASSIGN_OR_RETURN(
      EcdsaParameters ecdsa_parameters,
      EcdsaParameters::Builder()
          .SetCurveType(curve_type)
          .SetHashType(hash_type)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kIeeeP1363)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build());
  return EcdsaPublicKey::Create(ecdsa_parameters, public_point,
                                /*id_requirement=*/std::nullopt, token);
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
  custom_kid_ = std::string(custom_kid);
  return *this;
}

absl::StatusOr<std::optional<std::string>>
JwtEcdsaPublicKey::Builder::ComputeKid() {
  if (parameters_->GetKidStrategy() ==
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId) {
    if (custom_kid_.has_value()) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "Custom kid must not be set for KidStrategy::kBase64EncodedKeyId.");
    }
    std::string base64_kid;
    char buffer[4];
    internal::StoreBigEndian32(reinterpret_cast<uint8_t*>(buffer),
                               *id_requirement_);
    base64_kid = absl::WebSafeBase64Escape(absl::string_view(buffer, 4));
    return base64_kid;
  }
  if (parameters_->GetKidStrategy() ==
      JwtEcdsaParameters::KidStrategy::kCustom) {
    if (!custom_kid_.has_value()) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Custom kid must be set for KidStrategy::kCustom.");
    }
    return custom_kid_;
  }
  if (parameters_->GetKidStrategy() ==
      JwtEcdsaParameters::KidStrategy::kIgnored) {
    if (custom_kid_.has_value()) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "Custom kid must not be set for KidStrategy::kIgnored.");
    }
    return std::nullopt;
  }
  return absl::Status(absl::StatusCode::kInvalidArgument,
                      "Unknown kid strategy.");
}

absl::StatusOr<JwtEcdsaPublicKey> JwtEcdsaPublicKey::Builder::Build(
    PartialKeyAccessToken token) {
  if (!parameters_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "JWT ECDSA parameters must be specified.");
  }
  if (!public_point_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "JWT ECDSA public point must be specified.");
  }
  ABSL_ASSIGN_OR_RETURN(EcdsaPublicKey ecdsa_public_key,
                        ToEcdsaPublicKey(*parameters_, *public_point_, token));
  if (parameters_->HasIdRequirement() && !id_requirement_.has_value()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key without ID requirement with parameters with ID "
        "requirement");
  }
  if (!parameters_->HasIdRequirement() && id_requirement_.has_value()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key with ID requirement with parameters without ID "
        "requirement");
  }
  ABSL_ASSIGN_OR_RETURN(std::optional<std::string> kid, ComputeKid());
  return JwtEcdsaPublicKey(*parameters_, std::move(ecdsa_public_key),
                           id_requirement_, std::move(kid));
}

bool JwtEcdsaPublicKey::operator==(const Key& other) const {
  const JwtEcdsaPublicKey* that =
      dynamic_cast<const JwtEcdsaPublicKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return parameters_ == that->parameters_ &&
         ecdsa_public_key_ == that->ecdsa_public_key_ &&
         id_requirement_ == that->id_requirement_ && kid_ == that->kid_;
}

}  // namespace tink
}  // namespace crypto
