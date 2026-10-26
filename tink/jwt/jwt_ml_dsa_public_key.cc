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
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/jwt_ml_dsa_public_key.h"

#include <cstddef>
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
#include "absl/types/optional.h"
#include "tink/internal/endian.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_public_key.h"

namespace crypto {
namespace tink {
namespace {

static constexpr size_t kMlDsa44PublicKeyBytes = 1312;
static constexpr size_t kMlDsa65PublicKeyBytes = 1952;
static constexpr size_t kMlDsa87PublicKeyBytes = 2592;

absl::StatusOr<MlDsaPublicKey> ToMlDsaPublicKey(
    const JwtMlDsaParameters& parameters, absl::string_view public_key_bytes,
    PartialKeyAccessToken token) {
  MlDsaParameters::Instance instance;
  size_t expected_key_size;
  absl::string_view algorithm_name;
  switch (parameters.GetAlgorithm()) {
    case JwtMlDsaParameters::Algorithm::kMlDsa44:
      instance = MlDsaParameters::Instance::kMlDsa44;
      expected_key_size = kMlDsa44PublicKeyBytes;
      algorithm_name = "ML-DSA-44";
      break;
    case JwtMlDsaParameters::Algorithm::kMlDsa65:
      instance = MlDsaParameters::Instance::kMlDsa65;
      expected_key_size = kMlDsa65PublicKeyBytes;
      algorithm_name = "ML-DSA-65";
      break;
    case JwtMlDsaParameters::Algorithm::kMlDsa87:
      instance = MlDsaParameters::Instance::kMlDsa87;
      expected_key_size = kMlDsa87PublicKeyBytes;
      algorithm_name = "ML-DSA-87";
      break;
    default:
      return absl::InvalidArgumentError(
          "Invalid JWT ML-DSA algorithm. Only ML-DSA-44, ML-DSA-65 and "
          "ML-DSA-87 are currently supported.");
  }
  if (public_key_bytes.size() != expected_key_size) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Invalid JWT ML-DSA public key size. Only ", expected_key_size,
        "-byte keys are currently supported for ", algorithm_name, "."));
  }
  ABSL_ASSIGN_OR_RETURN(
      MlDsaParameters ml_dsa_parameters,
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kNoPrefix));
  return MlDsaPublicKey::Create(ml_dsa_parameters, public_key_bytes,
                                /*id_requirement=*/std::nullopt, token);
}

}  // namespace

JwtMlDsaPublicKey::Builder& JwtMlDsaPublicKey::Builder::SetParameters(
    const JwtMlDsaParameters& parameters) {
  parameters_ = parameters;
  return *this;
}

JwtMlDsaPublicKey::Builder& JwtMlDsaPublicKey::Builder::SetPublicKeyBytes(
    absl::string_view public_key_bytes) {
  public_key_bytes_ = public_key_bytes;
  return *this;
}

JwtMlDsaPublicKey::Builder& JwtMlDsaPublicKey::Builder::SetIdRequirement(
    int id_requirement) {
  id_requirement_ = id_requirement;
  return *this;
}

JwtMlDsaPublicKey::Builder& JwtMlDsaPublicKey::Builder::SetCustomKid(
    absl::string_view custom_kid) {
  custom_kid_ = std::string(custom_kid);
  return *this;
}

absl::StatusOr<std::optional<std::string>>
JwtMlDsaPublicKey::Builder::ComputeKid() {
  switch (parameters_->GetKidStrategy()) {
    case JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId: {
      if (custom_kid_.has_value()) {
        return absl::Status(
            absl::StatusCode::kInvalidArgument,
            "Custom kid must not be set for KidStrategy::kBase64EncodedKeyId.");
      }
      char buffer[4];
      internal::StoreBigEndian32(reinterpret_cast<uint8_t*>(buffer),
                                 *id_requirement_);
      return absl::WebSafeBase64Escape(absl::string_view(buffer, 4));
    }
    case JwtMlDsaParameters::KidStrategy::kCustom: {
      if (!custom_kid_.has_value()) {
        return absl::Status(absl::StatusCode::kInvalidArgument,
                            "Custom kid must be set for KidStrategy::kCustom.");
      }
      return custom_kid_;
    }
    case JwtMlDsaParameters::KidStrategy::kIgnored: {
      if (custom_kid_.has_value()) {
        return absl::Status(
            absl::StatusCode::kInvalidArgument,
            "Custom kid must not be set for KidStrategy::kIgnored.");
      }
      return std::nullopt;
    }
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unknown kid strategy.");
  }
}

absl::StatusOr<JwtMlDsaPublicKey> JwtMlDsaPublicKey::Builder::Build(
    PartialKeyAccessToken token) {
  if (!parameters_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "JWT ML-DSA parameters must be specified.");
  }
  if (!public_key_bytes_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "JWT ML-DSA public key bytes must be specified.");
  }
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

  ABSL_ASSIGN_OR_RETURN(
      MlDsaPublicKey ml_dsa_public_key,
      ToMlDsaPublicKey(*parameters_, *public_key_bytes_, token));
  ABSL_ASSIGN_OR_RETURN(std::optional<std::string> kid, ComputeKid());
  return JwtMlDsaPublicKey(*parameters_, std::move(ml_dsa_public_key),
                           id_requirement_, std::move(kid));
}

bool JwtMlDsaPublicKey::operator==(const Key& other) const {
  const JwtMlDsaPublicKey* that =
      dynamic_cast<const JwtMlDsaPublicKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return parameters_ == that->parameters_ &&
         ml_dsa_public_key_ == that->ml_dsa_public_key_ &&
         id_requirement_ == that->id_requirement_ && kid_ == that->kid_;
}

}  // namespace tink
}  // namespace crypto
