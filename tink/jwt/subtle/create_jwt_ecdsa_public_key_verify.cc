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

#include "tink/jwt/subtle/create_jwt_ecdsa_public_key_verify.h"

#include <memory>

#include "absl/status/statusor.h"
#include "tink/jwt/internal/jwt_ecdsa_verify.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/jwt/jwt_public_key_verify.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>>
CreateJwtEcdsaPublicKeyVerify(const JwtEcdsaPublicKey& key) {
  return jwt_internal::NewJwtEcdsaVerify(key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
