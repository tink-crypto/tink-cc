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

#ifndef TINK_MAC_SUBTLE_CREATE_AES_CMAC_MAC_H_
#define TINK_MAC_SUBTLE_CREATE_AES_CMAC_MAC_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/mac.h"
#include "tink/mac/aes_cmac_key.h"

namespace crypto {
namespace tink {
namespace subtle {

// Returns a `Mac` that computes AES-CMAC (RFC 4493) with `key`.
//
// This is a low-level API. Most users should instead obtain primitives from a
// `KeysetHandle` and a `Configuration`, which allows for key rotation.
//
// The returned `Mac` behaves like a keyset containing only `key`: it prepends
// `key.GetOutputPrefix()` to every tag, and expects it when verifying.
//
// Returns an error if the parameters of `key` are not supported by the
// implementation (currently only 16- or 32-byte keys and tags of at most 16
// bytes are supported).
absl::StatusOr<std::unique_ptr<Mac>> CreateAesCmacMac(const AesCmacKey& key);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_SUBTLE_CREATE_AES_CMAC_MAC_H_
