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

#ifndef TINK_AEAD_SUBTLE_CREATE_CHACHA20_POLY1305_AEAD_H_
#define TINK_AEAD_SUBTLE_CREATE_CHACHA20_POLY1305_AEAD_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/aead/chacha20_poly1305_key.h"

namespace crypto {
namespace tink {
namespace subtle {

// Returns an `Aead` that computes ChaCha20-Poly1305 with `key`.
//
// This is a low-level API. Most users should instead obtain primitives from a
// `KeysetHandle` and a `Configuration`, which allows for key rotation.
//
// The returned `Aead` behaves like a keyset containing only `key`: it prepends
// `key.GetOutputPrefix()` to every ciphertext, and expects it when decrypting.
absl::StatusOr<std::unique_ptr<Aead>> CreateChaCha20Poly1305Aead(
    const ChaCha20Poly1305Key& key);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_SUBTLE_CREATE_CHACHA20_POLY1305_AEAD_H_
