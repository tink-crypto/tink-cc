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

#ifndef TINK_HYBRID_SUBTLE_CREATE_ECIES_DECRYPT_H_
#define TINK_HYBRID_SUBTLE_CREATE_ECIES_DECRYPT_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/hybrid/ecies_private_key.h"
#include "tink/hybrid_decrypt.h"

namespace crypto {
namespace tink {
namespace subtle {

// Returns a `HybridDecrypt` that computes ECIES decryption with `key`.
//
// This is a low-level API. Most users should instead obtain primitives from a
// `KeysetHandle` and a `Configuration`, which allows for key rotation. Use
// this function only if the algorithm is fixed by a higher-level design, e.g.
// when implementing a protocol that internally uses ECIES.
//
// The returned `HybridDecrypt` behaves exactly like a keyset containing only
// `key`: it expects `key.GetOutputPrefix()` on every ciphertext and strips it
// before decrypting.
//
// Tink may change the underlying implementation at any time. Returns an error
// if the parameters of `key` are not supported by the implementation.
absl::StatusOr<std::unique_ptr<HybridDecrypt>> CreateEciesHybridDecrypt(
    const EciesPrivateKey& key);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_SUBTLE_CREATE_ECIES_DECRYPT_H_
