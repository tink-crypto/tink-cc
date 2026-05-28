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

#ifndef TINK_AEAD_INTERNAL_KMS_AEAD_CONFIG_2026_H_
#define TINK_AEAD_INTERNAL_KMS_AEAD_CONFIG_2026_H_

#include "absl/status/status.h"
#include "tink/configuration.h"

namespace crypto {
namespace tink {
namespace internal {

// Add 2026 recommended KMS AEAD key managers to `config`, used to generate
// primitives.
absl::Status AddKmsAead2026(Configuration& config);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_KMS_AEAD_CONFIG_2026_H_
