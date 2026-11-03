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

#ifndef TINK_HYBRID_SUBTLE_CREATE_HPKE_ENCRYPT_H_
#define TINK_HYBRID_SUBTLE_CREATE_HPKE_ENCRYPT_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid_encrypt.h"

namespace crypto {
namespace tink {
namespace subtle {

// Returns a `HybridEncrypt` that computes HPKE (RFC 9180) encryption with
// `key`.
//
// This is a low-level API. Most users should instead obtain primitives from a
// `KeysetHandle` and a `Configuration`, which allows for key rotation.
//
// The returned `HybridEncrypt` behaves like a keyset containing only `key`: it
// prepends `key.GetOutputPrefix()` to every ciphertext.
absl::StatusOr<std::unique_ptr<HybridEncrypt>> CreateHpkeHybridEncrypt(
    const HpkePublicKey& key);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_SUBTLE_CREATE_HPKE_ENCRYPT_H_
