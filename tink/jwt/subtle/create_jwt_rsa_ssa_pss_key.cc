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

#include "tink/jwt/subtle/create_jwt_rsa_ssa_pss_key.h"

#include <optional>
#include <string_view>

#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pss_key_creator.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pss_private_key.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<JwtRsaSsaPssPrivateKey> CreateJwtRsaSsaPssPrivateKey(
    const JwtRsaSsaPssParameters& parameters, std::optional<int> id_requirement,
    std::optional<std::string_view> custom_kid) {
  ABSL_ASSIGN_OR_RETURN(JwtRsaSsaPssPrivateKey key,
                        internal::CreatePrivateJwtRsaSsaPssKey(
                            parameters, id_requirement, custom_kid));
  return key;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
