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

#include "tink/signature/rsa_ssa_pkcs1_public_key.h"

#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/internal/output_prefix_util.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

util::StatusOr<std::string> ComputeOutputPrefix(
    const RsaSsaPkcs1Parameters& parameters,
    absl::optional<int> id_requirement) {
  switch (parameters.GetVariant()) {
    case RsaSsaPkcs1Parameters::Variant::kNoPrefix:
      return std::string("");  // Empty prefix.
    case RsaSsaPkcs1Parameters::Variant::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;
    case RsaSsaPkcs1Parameters::Variant::kCrunchy:
      if (!id_requirement.has_value()) {
        return util::Status(
            absl::StatusCode::kInvalidArgument,
            "ID requirement must have value with kCrunchy or kLegacy");
      }
      return internal::ComputeOutputPrefix(0, *id_requirement);
    case RsaSsaPkcs1Parameters::Variant::kTink:
      if (!id_requirement.has_value()) {
        return util::Status(absl::StatusCode::kInvalidArgument,
                            "ID requirement must have value with kTink");
      }
      return internal::ComputeOutputPrefix(1, *id_requirement);
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Invalid variant: ", parameters.GetVariant()));
  }
}

}  // namespace

util::StatusOr<RsaSsaPkcs1PublicKey> RsaSsaPkcs1PublicKey::Create(
    const RsaSsaPkcs1Parameters& parameters, const BigInteger& modulus,
    absl::optional<int> id_requirement, PartialKeyAccessToken token) {
  if (parameters.HasIdRequirement() && !id_requirement.has_value()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key without ID requirement with parameters with ID "
        "requirement");
  }
  if (!parameters.HasIdRequirement() && id_requirement.has_value()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key with ID requirement with parameters without ID "
        "requirement");
  }

  // Check if the modulus length matches the modulus_size_in_bits parameter.
  if (modulus.SizeInBytes() * 8 != parameters.GetModulusSizeInBits()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("Invalid modulus length (expected %d, got %d)",
                        parameters.GetModulusSizeInBits(),
                        modulus.SizeInBytes() * 8));
  }

  util::StatusOr<std::string> output_prefix =
      ComputeOutputPrefix(parameters, id_requirement);
  if (!output_prefix.ok()) {
    return output_prefix.status();
  }

  return RsaSsaPkcs1PublicKey(parameters, modulus, id_requirement,
                              *output_prefix);
}

bool RsaSsaPkcs1PublicKey::operator==(const Key& other) const {
  const RsaSsaPkcs1PublicKey* that =
      dynamic_cast<const RsaSsaPkcs1PublicKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (GetParameters() != that->GetParameters()) {
    return false;
  }
  if (id_requirement_ != that->id_requirement_) {
    return false;
  }
  return modulus_ == that->modulus_;
}

}  // namespace tink
}  // namespace crypto
