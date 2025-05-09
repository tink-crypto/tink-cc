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

#ifndef TINK_JWT_INTERNAL_JWT_MAC_CONFIG_V0_H_
#define TINK_JWT_INTERNAL_JWT_MAC_CONFIG_V0_H_

#include "absl/status/status.h"
#include "tink/configuration.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

// Add recommended JWT MAC primitive wrappers and key managers to `config`, used
// to generate primitives.
absl::Status AddJwtMacV0(Configuration& config);

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_MAC_CONFIG_V0_H_
