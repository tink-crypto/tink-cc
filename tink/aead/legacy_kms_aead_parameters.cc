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

#include "tink/aead/legacy_kms_aead_parameters.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

absl::StatusOr<LegacyKmsAeadParameters> LegacyKmsAeadParameters::Create(
    absl::string_view key_uri, Variant variant) {
  if (variant != Variant::kTink && variant != Variant::kNoPrefix) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create legacy KMS AEAD parameters with unknown variant.");
  }
  return LegacyKmsAeadParameters(key_uri, variant);
}

bool LegacyKmsAeadParameters::operator==(const Parameters& other) const {
  const LegacyKmsAeadParameters* that =
      dynamic_cast<const LegacyKmsAeadParameters*>(&other);
  return that != nullptr && key_uri_ == that->key_uri_ &&
         variant_ == that->variant_;
}

}  // namespace tink
}  // namespace crypto
