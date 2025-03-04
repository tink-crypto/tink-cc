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

#include "tink/prf/aes_cmac_prf_parameters.h"

#include "absl/status/status.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

absl::StatusOr<AesCmacPrfParameters> AesCmacPrfParameters::Create(
    int key_size_in_bytes) {
  if (key_size_in_bytes != 16 && key_size_in_bytes != 32) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Key size must be either 16 or 32 bytes.");
  }
  return AesCmacPrfParameters(key_size_in_bytes);
}

bool AesCmacPrfParameters::operator==(const Parameters& other) const {
  const AesCmacPrfParameters* that =
      dynamic_cast<const AesCmacPrfParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  return key_size_in_bytes_ == that->key_size_in_bytes_;
}

}  // namespace tink
}  // namespace crypto
