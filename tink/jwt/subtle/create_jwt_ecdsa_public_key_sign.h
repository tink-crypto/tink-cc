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

#ifndef TINK_JWT_SUBTLE_CREATE_JWT_ECDSA_PUBLIC_KEY_SIGN_H_
#define TINK_JWT_SUBTLE_CREATE_JWT_ECDSA_PUBLIC_KEY_SIGN_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/jwt/jwt_ecdsa_private_key.h"
#include "tink/jwt/jwt_public_key_sign.h"

namespace crypto {
namespace tink {
namespace subtle {

// Creates a new JwtPublicKeySign primitive from a JwtEcdsaPrivateKey.
absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> CreateJwtEcdsaPublicKeySign(
    const JwtEcdsaPrivateKey& key);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_SUBTLE_CREATE_JWT_ECDSA_PUBLIC_KEY_SIGN_H_
