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

#include "tink/jwt/subtle/create_jwt_hmac.h"

#include <memory>

#include "absl/status/statusor.h"
#include "tink/jwt/internal/jwt_hmac.h"
#include "tink/jwt/jwt_hmac_key.h"
#include "tink/jwt/jwt_mac.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<std::unique_ptr<JwtMac>> CreateJwtHmac(const JwtHmacKey& key) {
  return jwt_internal::NewJwtHmac(key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
