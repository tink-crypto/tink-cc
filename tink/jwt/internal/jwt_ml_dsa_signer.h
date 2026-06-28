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

#ifndef TINK_JWT_INTERNAL_JWT_ML_DSA_SIGNER_H_
#define TINK_JWT_INTERNAL_JWT_ML_DSA_SIGNER_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/jwt/internal/jwt_public_key_sign_internal.h"
#include "tink/jwt/jwt_ml_dsa_private_key.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

absl::StatusOr<std::unique_ptr<JwtPublicKeySignInternal>>
NewJwtMlDsaSignInternal(const JwtMlDsaPrivateKey& jwt_ml_dsa_private_key);

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_ML_DSA_SIGNER_H_
