// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/mac/aes_cmac_key.h"

#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "tink/internal/output_prefix_util.h"
#include "tink/key.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

absl::StatusOr<AesCmacKey> AesCmacKey::Create(
    const AesCmacParameters& parameters, RestrictedData key_bytes,
    absl::optional<int> id_requirement, PartialKeyAccessToken token) {
  if (parameters.KeySizeInBytes() != key_bytes.size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Key size does not match AES-CMAC parameters");
  }
  if (parameters.HasIdRequirement() && !id_requirement.has_value()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key without ID requirement with parameters with ID "
        "requirement");
  }
  if (!parameters.HasIdRequirement() && id_requirement.has_value()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key with ID requirement with parameters without ID "
        "requirement");
  }
  absl::StatusOr<std::string> output_prefix =
      ComputeOutputPrefix(parameters, id_requirement);
  if (!output_prefix.ok()) {
    return output_prefix.status();
  }
  return AesCmacKey(parameters, std::move(key_bytes), id_requirement,
                    *std::move(output_prefix));
}

absl::StatusOr<std::string> AesCmacKey::ComputeOutputPrefix(
    const AesCmacParameters& parameters, absl::optional<int> id_requirement) {
  switch (parameters.GetVariant()) {
    case AesCmacParameters::Variant::kNoPrefix:
      return std::string("");  // Empty prefix.
    case AesCmacParameters::Variant::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;
    case AesCmacParameters::Variant::kCrunchy:
      if (!id_requirement.has_value()) {
        return absl::Status(
            absl::StatusCode::kInvalidArgument,
            "id requirement must have value with kCrunchy or kLegacy");
      }
      return internal::ComputeOutputPrefix(0, *id_requirement);
    case AesCmacParameters::Variant::kTink:
      if (!id_requirement.has_value()) {
        return absl::Status(absl::StatusCode::kInvalidArgument,
                            "id requirement must have value with kTink");
      }
      return internal::ComputeOutputPrefix(1, *id_requirement);
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Invalid variant: ", parameters.GetVariant()));
  }
}

bool AesCmacKey::operator==(const Key& other) const {
  const AesCmacKey* that = dynamic_cast<const AesCmacKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (GetParameters() != that->GetParameters()) {
    return false;
  }
  if (id_requirement_ != that->id_requirement_) {
    return false;
  }
  return key_bytes_ == that->key_bytes_;
}

}  // namespace tink
}  // namespace crypto
