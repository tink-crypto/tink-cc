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

#ifndef TINK_SIGNATURE_INTERNAL_ML_DSA_SIGN_KEY_MANAGER_H_
#define TINK_SIGNATURE_INTERNAL_ML_DSA_SIGN_KEY_MANAGER_H_

#include <memory>

#include "tink/key_manager.h"
#include "tink/public_key_sign.h"

namespace crypto {
namespace tink {
namespace internal {

std::unique_ptr<KeyManager<PublicKeySign>> MakeMlDsaSignKeyManager();

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_ML_DSA_SIGN_KEY_MANAGER_H_
