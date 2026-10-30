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

#include "tink/aead/subtle/create_aes_gcm_cord_aead.h"

#include <memory>

#include "absl/status/statusor.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/internal/cord_aes_gcm_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<std::unique_ptr<CordAead>> CreateAesGcmCordAead(
    const AesGcmKey& key) {
  return internal::CordAesGcmBoringSsl::New(key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
