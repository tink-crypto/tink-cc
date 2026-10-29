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

#ifndef TINK_AEAD_INTERNAL_ZERO_COPY_CHACHA20_POLY1305_BORINGSSL_H_
#define TINK_AEAD_INTERNAL_ZERO_COPY_CHACHA20_POLY1305_BORINGSSL_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead/chacha20_poly1305_key.h"
#include "tink/aead/internal/ssl_aead.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/internal/fips_utils.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

// Constructs a new ZeroCopyAead cipher for ChaCha20-Poly1305.
// Currently supported key size is 256 bits.
// Currently supported nonce size is 12 bytes.
// The tag size is fixed to 16 bytes.
absl::StatusOr<std::unique_ptr<ZeroCopyAead>> ChaCha20Poly1305ZeroCopyAead(
    const ChaCha20Poly1305Key& key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_ZERO_COPY_CHACHA20_POLY1305_BORINGSSL_H_
