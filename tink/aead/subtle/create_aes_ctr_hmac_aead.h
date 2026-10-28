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

#ifndef TINK_AEAD_SUBTLE_CREATE_AES_CTR_HMAC_AEAD_H_
#define TINK_AEAD_SUBTLE_CREATE_AES_CTR_HMAC_AEAD_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/aead/aes_ctr_hmac_aead_key.h"

namespace crypto {
namespace tink {
namespace subtle {

// Returns an `Aead` that computes AES-CTR-HMAC-AEAD (Encrypt-then-MAC using
// AES-CTR and HMAC) with `key`.
//
// This is a low-level API. Most users should instead obtain primitives from a
// `KeysetHandle` and a `Configuration`, which allows for key rotation.
//
// The returned `Aead` behaves like a keyset containing only `key`: it prepends
// `key.GetOutputPrefix()` to every ciphertext, and expects it when decrypting.
//
// Returns an error if the parameters of `key` are not supported by the
// implementation (for example, 24-byte AES keys are not supported).
absl::StatusOr<std::unique_ptr<Aead>> CreateAesCtrHmacAead(
    const AesCtrHmacAeadKey& key);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_SUBTLE_CREATE_AES_CTR_HMAC_AEAD_H_
