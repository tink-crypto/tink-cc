// Copyright 2024 Google LLC
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

#ifndef TINK_INTERNAL_INTERNAL_INSECURE_SECRET_KEY_ACCESS_H_
#define TINK_INTERNAL_INTERNAL_INSECURE_SECRET_KEY_ACCESS_H_

#include "tink/secret_key_access_token.h"

namespace crypto {
namespace tink {
namespace internal {

// Returns a `SecretKeyAccessToken`.
// This function must NOT be used outside of crypto library team-owned code.
// We use this in header files to ensure that we can BUILD-visibility restrict
// the usual token -- users can be expected not to write code using things
// in crypto::tink::internal namespace (or we might simply break them).
SecretKeyAccessToken GetInsecureSecretKeyAccessInternal();

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_INTERNAL_INSECURE_SECRET_KEY_ACCESS_H_
