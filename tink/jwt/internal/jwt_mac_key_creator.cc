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

#include "tink/jwt/internal/jwt_mac_key_creator.h"

#include <optional>
#include <string_view>

#include "absl/status/statusor.h"
#include "tink/jwt/jwt_hmac_key.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<JwtHmacKey> CreateJwtMacKey(
    const JwtHmacParameters& parameters, std::optional<int> id_requirement,
    std::optional<std::string_view> custom_kid) {
  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetParameters(parameters)
          .SetKeyBytes(RestrictedData(parameters.KeySizeInBytes()));
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(*id_requirement);
  }
  if (custom_kid.has_value()) {
    builder.SetCustomKid(*custom_kid);
  }
  return builder.Build(GetPartialKeyAccess());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
