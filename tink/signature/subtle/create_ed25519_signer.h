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

#ifndef TINK_SIGNATURE_SUBTLE_CREATE_ED25519_SIGNER_H_
#define TINK_SIGNATURE_SUBTLE_CREATE_ED25519_SIGNER_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ed25519_private_key.h"

namespace crypto {
namespace tink {
namespace subtle {

// Returns a `PublicKeySign` that computes Ed25519 signatures with `key`.
//
// This is a low-level API. Most users should instead obtain primitives from a
// `KeysetHandle` and a `Configuration`, which allows for key rotation.
//
// The returned `PublicKeySign` behaves like a keyset containing only `key`: it
// prepends `key.GetOutputPrefix()` to every signature.
absl::StatusOr<std::unique_ptr<PublicKeySign>> CreateEd25519PublicKeySign(
    const Ed25519PrivateKey& key);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_SUBTLE_CREATE_ED25519_SIGNER_H_
