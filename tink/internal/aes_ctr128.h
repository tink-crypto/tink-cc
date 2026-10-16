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
#ifndef TINK_INTERNAL_AES_CTR128_H_
#define TINK_INTERNAL_AES_CTR128_H_

#include <cstdint>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/aes.h"
#include "tink/internal/aes_util.h"

namespace crypto {
namespace tink {
namespace internal {

// Wrapper for BoringSSL's low-level function that encrypts/decrypts (same
// operation in CTR mode) `data`, with IV `iv` and key `key`. The result is
// written to `out`. `out` may fully overlap with `data`; partial overlaps will
// result in an kInvalidArgument error. `iv` is incremented of the number of
// blocks that were encrypted/decrypted.
absl::Status AesCtr128Crypt(absl::string_view data, uint8_t iv[AesBlockSize()],
                            const AES_KEY* key, absl::Span<char> out);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_AES_CTR128_H_
