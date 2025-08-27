// Copyright 2024 Google LLC
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

#ifndef TINK_KEYDERIVATION_INTERNAL_KEY_DERIVERS_H_
#define TINK_KEYDERIVATION_INTERNAL_KEY_DERIVERS_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/input_stream.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

// Derives a key from the given parameters and randomness.
//
// The following key types are supported:
// - AEAD: AES-CTR-HMAC, AES-GCM, XChaCha20-Poly1305
// - Deterministic AEAD: AES-SIV
// - MAC: HMAC
// - PRF: HKDF PRF
// - Signature: ECDSA, Ed25519
//
// The following key types are pending support:
// - JWT: JWT HMAC
// - PRF: AES-CMAC PRF, HMAC PRF
// - Streaming AEAD: AES-CTR-HMAC, AES-GCM-HKDF
//
// TODO: b/314831964 - Add support for remaining key types.
absl::StatusOr<std::unique_ptr<crypto::tink::Key>> DeriveKey(
    const crypto::tink::Parameters& params,
    crypto::tink::InputStream* randomness);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYDERIVATION_INTERNAL_KEY_DERIVERS_H_
