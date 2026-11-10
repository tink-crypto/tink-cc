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

#ifndef TINK_DAEAD_SUBTLE_CREATE_AES_SIV_DETERMINISTIC_AEADS_H_
#define TINK_DAEAD_SUBTLE_CREATE_AES_SIV_DETERMINISTIC_AEADS_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/daead/aes_siv_key.h"
#include "tink/daead/subtle/deterministic_aeads.h"

namespace crypto {
namespace tink {
namespace subtle {

// Returns a `DeterministicAeads` that computes AES-SIV (RFC 5297) with `key`.
//
// This is a low-level API. Most users should instead obtain primitives from a
// `KeysetHandle` and a `Configuration`, which allows for key rotation. Use
// this function only if the algorithm is fixed by a higher-level design, e.g.
// when implementing a protocol that internally uses AES-SIV with multiple
// associated data inputs.
//
// The returned `DeterministicAeads` prepends `key.GetOutputPrefix()` to every
// ciphertext, and expects it when decrypting.
//
// Tink may change the underlying implementation at any time. Returns an error
// if the parameters of `key` are not supported by the implementation
// (currently 32-byte and 64-byte keys and up to 126 associated data inputs are
// supported).
absl::StatusOr<std::unique_ptr<DeterministicAeads>>
CreateAesSivDeterministicAeads(const AesSivKey& key);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_DAEAD_SUBTLE_CREATE_AES_SIV_DETERMINISTIC_AEADS_H_
