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

#ifndef TINK_HYBRID_SUBTLE_CREATE_HPKE_DECRYPT_H_
#define TINK_HYBRID_SUBTLE_CREATE_HPKE_DECRYPT_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid_decrypt.h"

namespace crypto {
namespace tink {
namespace subtle {

// Returns a `HybridDecrypt` that computes HPKE (RFC 9180) decryption with
// `key`.
//
// This is a low-level API. Most users should instead obtain primitives from a
// `KeysetHandle` and a `Configuration`, which allows for key rotation.
//
// The returned `HybridDecrypt` behaves like a keyset containing only `key`: it
// expects `key.GetOutputPrefix()` at the beginning of every ciphertext.
absl::StatusOr<std::unique_ptr<HybridDecrypt>> CreateHpkeDecrypt(
    const HpkePrivateKey& key);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_SUBTLE_CREATE_HPKE_DECRYPT_H_
