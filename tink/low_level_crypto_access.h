// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_LOW_LEVEL_CRYPTO_ACCESS_H_
#define TINK_LOW_LEVEL_CRYPTO_ACCESS_H_

#include "tink/low_level_crypto_access_token.h"

namespace crypto {
namespace tink {

// Returns a `LowLevelCryptoAccessToken`.
//
// This function can be used to access low level cryptography primitives. Within
// Google, access to this function is restricted by the build system. Outside of
// Google, users can search their codebase for `GetLowLevelCryptoAccess()` to
// find instances where it is used.
inline LowLevelCryptoAccessToken GetLowLevelCryptoAccess() {
  return LowLevelCryptoAccessToken();
}

}  // namespace tink
}  // namespace crypto

#endif  // TINK_LOW_LEVEL_CRYPTO_ACCESS_H_
