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

#ifndef TINK_JWT_INTERNAL_JWT_MAC_KEY_CREATOR_H_
#define TINK_JWT_INTERNAL_JWT_MAC_KEY_CREATOR_H_

#include <optional>
#include <string_view>

#include "absl/status/statusor.h"
#include "tink/jwt/jwt_hmac_key.h"
#include "tink/jwt/jwt_hmac_parameters.h"

namespace crypto {
namespace tink {
namespace internal {

// Generates a new standalone JwtHmacKey from parameters.
//
// Preconditions for optional parameters:
// - `id_requirement` is required if and only if `parameters.HasIdRequirement()`
//   is true (`KidStrategy::kBase64EncodedKeyId`).
// - `custom_kid` is required if and only if `parameters.GetKidStrategy() ==
//   JwtHmacParameters::KidStrategy::kCustom`.
// - Both should be omitted for `KidStrategy::kIgnored`.
absl::StatusOr<JwtHmacKey> CreateJwtMacKey(
    const JwtHmacParameters& parameters,
    std::optional<int> id_requirement = std::nullopt,
    std::optional<std::string_view> custom_kid = std::nullopt);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_MAC_KEY_CREATOR_H_
