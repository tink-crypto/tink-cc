// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_SIGNATURE_INTERNAL_ECDSA_PREHASH_BORINGSSL_H_
#define TINK_SIGNATURE_INTERNAL_ECDSA_PREHASH_BORINGSSL_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/prehash.h"

namespace crypto {
namespace tink {
namespace internal {

// Creates a new Prehash primitive for the given ECDSA `public_key`.
// Computes the hash digest specified by `public_key.GetParameters()` and
// prepends the prehash prefix ("0xff || big_endian(key_id)" for keys with an
// ID requirement, or empty string for kNoPrefix keys). Rejects kLegacy keys.
absl::StatusOr<std::unique_ptr<Prehash>> NewEcdsaPrehashBoringSsl(
    const EcdsaPublicKey& public_key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_ECDSA_PREHASH_BORINGSSL_H_
