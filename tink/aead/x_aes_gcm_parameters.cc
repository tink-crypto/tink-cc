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

#include "tink/aead/x_aes_gcm_parameters.h"

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<XAesGcmParameters> XAesGcmParameters::Create(
    Variant variant, int salt_size_bytes) {
  if (variant != Variant::kTink && variant != Variant::kNoPrefix) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create X-AES-GCM parameters with unknown variant.");
  }
  if (salt_size_bytes < 8 || salt_size_bytes > 12) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Salt size must be between 8 and 12 bytes.");
  }
  return XAesGcmParameters(variant, salt_size_bytes);
}

bool XAesGcmParameters::operator==(const Parameters& other) const {
  const XAesGcmParameters* that =
      dynamic_cast<const XAesGcmParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (salt_size_bytes_ != that->salt_size_bytes_) {
    return false;
  }
  if (variant_ != that->variant_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
