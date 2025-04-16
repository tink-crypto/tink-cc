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

#include "tink/jwt/jwt_rsa_ssa_pkcs1_public_key.h"

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/internal/endian.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"

namespace crypto {
namespace tink {

JwtRsaSsaPkcs1PublicKey::Builder&
JwtRsaSsaPkcs1PublicKey::Builder::SetParameters(
    const JwtRsaSsaPkcs1Parameters& parameters) {
  parameters_ = parameters;
  return *this;
}

JwtRsaSsaPkcs1PublicKey::Builder& JwtRsaSsaPkcs1PublicKey::Builder::SetModulus(
    const BigInteger& modulus) {
  modulus_ = modulus;
  return *this;
}

JwtRsaSsaPkcs1PublicKey::Builder&
JwtRsaSsaPkcs1PublicKey::Builder::SetIdRequirement(int id_requirement) {
  id_requirement_ = id_requirement;
  return *this;
}

JwtRsaSsaPkcs1PublicKey::Builder&
JwtRsaSsaPkcs1PublicKey::Builder::SetCustomKid(absl::string_view custom_kid) {
  custom_kid_ = custom_kid.data();
  return *this;
}

absl::StatusOr<absl::optional<std::string>>
JwtRsaSsaPkcs1PublicKey::Builder::ComputeKid() {
  if (parameters_->GetKidStrategy() ==
      JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId) {
    if (custom_kid_.has_value()) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "Custom kid must not be set for KidStrategy::kBase64EncodedKeyId.");
    }
    std::string base64_kid;
    char buffer[4];
    crypto::tink::internal::StoreBigEndian32(reinterpret_cast<uint8_t*>(buffer),
                                             *id_requirement_);
    absl::WebSafeBase64Escape(absl::string_view(buffer, 4), &base64_kid);
    return base64_kid;
  }
  if (parameters_->GetKidStrategy() ==
      JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    if (!custom_kid_.has_value()) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Custom kid must be set for KidStrategy::kCustom.");
    }
    return custom_kid_;
  }
  if (parameters_->GetKidStrategy() ==
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored) {
    if (custom_kid_.has_value()) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "Custom kid must not be set for KidStrategy::kIgnored.");
    }
    return absl::nullopt;
  }
  return absl::Status(absl::StatusCode::kInvalidArgument,
                      "Unknown kid strategy.");
}

absl::StatusOr<JwtRsaSsaPkcs1PublicKey> JwtRsaSsaPkcs1PublicKey::Builder::Build(
    PartialKeyAccessToken token) {
  if (!parameters_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "JWT RSA-SSA-PKCS1 parameters must be specified.");
  }
  if (!modulus_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "JWT RSA-SSA-PKCS1 modulus must be specified.");
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
  // Check if the modulus length matches the modulus_size_in_bits parameter.
  if (modulus_->SizeInBytes() * 8 != parameters_->GetModulusSizeInBits()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("Invalid modulus length (expected %d, got %d)",
                        parameters_->GetModulusSizeInBits(),
                        modulus_->SizeInBytes() * 8));
  }
  absl::StatusOr<absl::optional<std::string>> kid = ComputeKid();
  if (!kid.ok()) {
    return kid.status();
  }
  return JwtRsaSsaPkcs1PublicKey(*parameters_, *modulus_, id_requirement_,
                                 std::move(*kid));
}

bool JwtRsaSsaPkcs1PublicKey::operator==(const Key& other) const {
  const JwtRsaSsaPkcs1PublicKey* that =
      dynamic_cast<const JwtRsaSsaPkcs1PublicKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return parameters_ == that->parameters_ && modulus_ == that->modulus_ &&
         id_requirement_ == that->id_requirement_ && kid_ == that->kid_;
}

}  // namespace tink
}  // namespace crypto
