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

#ifndef TINK_JWT_INTERNAL_JWT_ML_DSA_SIGN_KEY_MANAGER_H_
#define TINK_JWT_INTERNAL_JWT_ML_DSA_SIGN_KEY_MANAGER_H_

#include <memory>

#include "tink/jwt/internal/jwt_public_key_sign_internal.h"
#include "tink/key_manager.h"

namespace crypto {
namespace tink {
namespace internal {

std::unique_ptr<KeyManager<JwtPublicKeySignInternal>>
MakeJwtMlDsaSignKeyManager();

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_ML_DSA_SIGN_KEY_MANAGER_H_
