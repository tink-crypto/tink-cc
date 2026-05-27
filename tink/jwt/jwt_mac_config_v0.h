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

#ifndef TINK_JWT_JWT_MAC_CONFIG_V0_H_
#define TINK_JWT_JWT_MAC_CONFIG_V0_H_

#include "absl/base/attributes.h"
#include "tink/configuration.h"
#include "tink/jwt/jwt_mac_config_2026.h"

namespace crypto {
namespace tink {

// Deprecated. Use ConfigJwtMac2026() instead.
ABSL_DEPRECATED("Use ConfigJwtMac2026() instead.")
inline const Configuration& ConfigJwtMacV0() { return ConfigJwtMac2026(); }

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_MAC_CONFIG_V0_H_
