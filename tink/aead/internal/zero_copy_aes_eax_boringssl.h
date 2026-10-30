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
///////////////////////////////////////////////////////////////////////////////

#ifndef TINK_AEAD_INTERNAL_ZERO_COPY_AES_EAX_BORINGSSL_H_
#define TINK_AEAD_INTERNAL_ZERO_COPY_AES_EAX_BORINGSSL_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/aead/aes_eax_key.h"
#include "tink/aead/internal/zero_copy_aead.h"

namespace crypto {
namespace tink {
namespace internal {

// Constructs a new ZeroCopyAead cipher for AES-EAX.
// Currently supported key sizes are 128 and 256 bits.
// Currently supported nonce sizes are 12 and 16 bytes.
// The tag size is fixed to 16 bytes.
absl::StatusOr<std::unique_ptr<ZeroCopyAead>> AesEaxZeroCopyAead(
    const AesEaxKey& key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_ZERO_COPY_AES_EAX_BORINGSSL_H_
