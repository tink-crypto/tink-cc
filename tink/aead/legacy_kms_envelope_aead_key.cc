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

#include "tink/aead/legacy_kms_envelope_aead_key.h"

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "tink/aead/legacy_kms_envelope_aead_parameters.h"
#include "tink/internal/output_prefix_util.h"
#include "tink/key.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

absl::StatusOr<std::string> ComputeOutputPrefix(
    LegacyKmsEnvelopeAeadParameters::Variant variant,
    absl::optional<int> id_requirement) {
  switch (variant) {
    case LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix:
      return std::string("");  // Empty prefix.
    case LegacyKmsEnvelopeAeadParameters::Variant::kTink:
      if (!id_requirement.has_value()) {
        return absl::Status(absl::StatusCode::kInvalidArgument,
                            "id requirement must have value with kTink");
      }
      return internal::ComputeOutputPrefix(1, *id_requirement);
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Invalid variant: ", variant));
  }
}

}  // namespace

absl::StatusOr<LegacyKmsEnvelopeAeadKey> LegacyKmsEnvelopeAeadKey::Create(
    const LegacyKmsEnvelopeAeadParameters& parameters,
    absl::optional<int> id_requirement) {
  if (parameters.GetVariant() !=
          LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix &&
      !id_requirement.has_value()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key without ID requirement with variant with ID "
        "requirement");
  }
  if (parameters.GetVariant() ==
          LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix &&
      id_requirement.has_value()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key with ID requirement with variant without ID "
        "requirement");
  }
  absl::StatusOr<std::string> output_prefix =
      ComputeOutputPrefix(parameters.GetVariant(), id_requirement);
  if (!output_prefix.ok()) {
    return output_prefix.status();
  }
  return LegacyKmsEnvelopeAeadKey(parameters, id_requirement,
                                  *std::move(output_prefix));
}

bool LegacyKmsEnvelopeAeadKey::operator==(const Key& other) const {
  const LegacyKmsEnvelopeAeadKey* that =
      dynamic_cast<const LegacyKmsEnvelopeAeadKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (GetParameters() != that->GetParameters()) {
    return false;
  }
  return id_requirement_ == that->id_requirement_;
}

}  // namespace tink
}  // namespace crypto
