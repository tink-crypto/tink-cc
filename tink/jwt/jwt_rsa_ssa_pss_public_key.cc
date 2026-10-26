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

#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/internal/endian.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"

namespace crypto {
namespace tink {
namespace {

absl::StatusOr<RsaSsaPssPublicKey> ToRsaSsaPssPublicKey(
    const JwtRsaSsaPssParameters& parameters, const BigInteger& modulus,
    PartialKeyAccessToken token) {
  RsaSsaPssParameters::HashType hash_type;
  int salt_length_in_bytes;
  // See https://datatracker.ietf.org/doc/html/rfc7518#section-3.5.
  switch (parameters.GetAlgorithm()) {
    case JwtRsaSsaPssParameters::Algorithm::kPs256:
      hash_type = RsaSsaPssParameters::HashType::kSha256;
      salt_length_in_bytes = 32;
      break;
    case JwtRsaSsaPssParameters::Algorithm::kPs384:
      hash_type = RsaSsaPssParameters::HashType::kSha384;
      salt_length_in_bytes = 48;
      break;
    case JwtRsaSsaPssParameters::Algorithm::kPs512:
      hash_type = RsaSsaPssParameters::HashType::kSha512;
      salt_length_in_bytes = 64;
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unknown algorithm.");
  }
  ABSL_ASSIGN_OR_RETURN(
      RsaSsaPssParameters rsa_ssa_pss_parameters,
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(parameters.GetModulusSizeInBits())
          .SetPublicExponent(parameters.GetPublicExponent())
          .SetSigHashType(hash_type)
          .SetMgf1HashType(hash_type)
          .SetSaltLengthInBytes(salt_length_in_bytes)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build());
  return RsaSsaPssPublicKey::Create(rsa_ssa_pss_parameters, modulus,
                                    /*id_requirement=*/std::nullopt, token);
}

}  // namespace

JwtRsaSsaPssPublicKey::Builder& JwtRsaSsaPssPublicKey::Builder::SetParameters(
    const JwtRsaSsaPssParameters& parameters) {
  parameters_ = parameters;
  return *this;
}

JwtRsaSsaPssPublicKey::Builder& JwtRsaSsaPssPublicKey::Builder::SetModulus(
    const BigInteger& modulus) {
  modulus_ = modulus;
  return *this;
}

JwtRsaSsaPssPublicKey::Builder&
JwtRsaSsaPssPublicKey::Builder::SetIdRequirement(int id_requirement) {
  id_requirement_ = id_requirement;
  return *this;
}

JwtRsaSsaPssPublicKey::Builder& JwtRsaSsaPssPublicKey::Builder::SetCustomKid(
    absl::string_view custom_kid) {
  custom_kid_ = std::string(custom_kid);
  return *this;
}

absl::StatusOr<std::optional<std::string>>
JwtRsaSsaPssPublicKey::Builder::ComputeKid() {
  if (parameters_->GetKidStrategy() ==
      JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId) {
    if (custom_kid_.has_value()) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "Custom kid must not be set for KidStrategy::kBase64EncodedKeyId.");
    }
    std::string base64_kid;
    char buffer[4];
    crypto::tink::internal::StoreBigEndian32(reinterpret_cast<uint8_t*>(buffer),
                                             *id_requirement_);
    base64_kid = absl::WebSafeBase64Escape(absl::string_view(buffer, 4));
    return base64_kid;
  }
  if (parameters_->GetKidStrategy() ==
      JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    if (!custom_kid_.has_value()) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Custom kid must be set for KidStrategy::kCustom.");
    }
    return custom_kid_;
  }
  if (parameters_->GetKidStrategy() ==
      JwtRsaSsaPssParameters::KidStrategy::kIgnored) {
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

absl::StatusOr<JwtRsaSsaPssPublicKey> JwtRsaSsaPssPublicKey::Builder::Build(
    PartialKeyAccessToken token) {
  if (!parameters_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "JWT RSA-SSA-PSS parameters must be specified.");
  }
  if (!modulus_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "JWT RSA-SSA-PSS modulus must be specified.");
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
  ABSL_ASSIGN_OR_RETURN(RsaSsaPssPublicKey rsa_ssa_pss_public_key,
                        ToRsaSsaPssPublicKey(*parameters_, *modulus_, token));
  ABSL_ASSIGN_OR_RETURN(std::optional<std::string> kid, ComputeKid());
  return JwtRsaSsaPssPublicKey(*parameters_, std::move(rsa_ssa_pss_public_key),
                               id_requirement_, std::move(kid));
}

bool JwtRsaSsaPssPublicKey::operator==(const Key& other) const {
  const JwtRsaSsaPssPublicKey* that =
      dynamic_cast<const JwtRsaSsaPssPublicKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return parameters_ == that->parameters_ &&
         rsa_ssa_pss_public_key_ == that->rsa_ssa_pss_public_key_ &&
         id_requirement_ == that->id_requirement_ && kid_ == that->kid_;
}

}  // namespace tink
}  // namespace crypto
