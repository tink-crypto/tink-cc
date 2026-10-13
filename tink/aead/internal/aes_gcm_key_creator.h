// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, embodiment or
// conditions of any kind, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#ifndef TINK_AEAD_INTERNAL_AES_GCM_KEY_CREATOR_H_
#define TINK_AEAD_INTERNAL_AES_GCM_KEY_CREATOR_H_

#include <memory>
#include <optional>

#include "absl/status/statusor.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/key.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<Key>> CreateAesGcmKey(
    const AesGcmParameters& parameters, std::optional<int> id_requirement);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_AES_GCM_KEY_CREATOR_H_
