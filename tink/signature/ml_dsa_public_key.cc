// Copyright 2024 Google LLC
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

#include "tink/signature/ml_dsa_public_key.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "openssl/mldsa.h"
#include "tink/internal/output_prefix_util.h"
#include "tink/key.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

absl::StatusOr<std::string> ComputeOutputPrefix(
    const MlDsaParameters& parameters, absl::optional<int> id_requirement) {
  switch (parameters.GetVariant()) {
    case MlDsaParameters::Variant::kNoPrefix:
      return std::string("");  // Empty prefix.
    case MlDsaParameters::Variant::kTink:
      if (!id_requirement.has_value()) {
        return absl::Status(absl::StatusCode::kInvalidArgument,
                            "ID requirement must have value with kTink");
      }
      return internal::ComputeOutputPrefix(1, *id_requirement);
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Invalid variant: ", parameters.GetVariant()));
  }
}

}  // namespace

absl::StatusOr<MlDsaPublicKey> MlDsaPublicKey::Create(
    const MlDsaParameters& parameters, absl::string_view public_key_bytes,
    absl::optional<int> id_requirement, PartialKeyAccessToken token) {
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

  if (parameters.GetInstance() != MlDsaParameters::Instance::kMlDsa65) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid ML-DSA instance. Only ML-DSA-65 is "
                        "currently supported.");
  }

  if (public_key_bytes.size() != MLDSA65_PUBLIC_KEY_BYTES) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Invalid ML-DSA public key size. Only ",
                                     MLDSA65_PUBLIC_KEY_BYTES,
                                     "-byte keys are currently supported."));
  }

  absl::StatusOr<std::string> output_prefix =
      ComputeOutputPrefix(parameters, id_requirement);
  if (!output_prefix.ok()) {
    return output_prefix.status();
  }
  return MlDsaPublicKey(parameters, public_key_bytes, id_requirement,
                        *output_prefix);
}

bool MlDsaPublicKey::operator==(const Key& other) const {
  const MlDsaPublicKey* that = dynamic_cast<const MlDsaPublicKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return GetParameters() == that->GetParameters() &&
         public_key_bytes_ == that->public_key_bytes_ &&
         id_requirement_ == that->id_requirement_;
}

}  // namespace tink
}  // namespace crypto
