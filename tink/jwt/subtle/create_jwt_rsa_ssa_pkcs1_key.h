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

#ifndef TINK_JWT_SUBTLE_CREATE_JWT_RSA_SSA_PKCS1_KEY_H_
#define TINK_JWT_SUBTLE_CREATE_JWT_RSA_SSA_PKCS1_KEY_H_

#include <optional>
#include <string_view>

#include "absl/status/statusor.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"

namespace crypto {
namespace tink {
namespace subtle {

// Most users should not call this API directly. Instead, most users should
// utilize keysets to ensure key rotation.
//
// Generates a new standalone JwtRsaSsaPkcs1PrivateKey from parameters.
absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> CreateJwtRsaSsaPkcs1PrivateKey(
    const JwtRsaSsaPkcs1Parameters& parameters,
    std::optional<int> id_requirement = std::nullopt,
    std::optional<std::string_view> custom_kid = std::nullopt);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_SUBTLE_CREATE_JWT_RSA_SSA_PKCS1_KEY_H_
