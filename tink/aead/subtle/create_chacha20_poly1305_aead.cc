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

#include "tink/aead/subtle/create_chacha20_poly1305_aead.h"

#include <memory>
#include <utility>

#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/aead/chacha20_poly1305_key.h"
#include "tink/aead/internal/aead_from_zero_copy.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/aead/internal/zero_copy_chacha20_poly1305_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<std::unique_ptr<Aead>> CreateChaCha20Poly1305Aead(
    const ChaCha20Poly1305Key& key) {
  ABSL_ASSIGN_OR_RETURN(std::unique_ptr<internal::ZeroCopyAead> zero_copy_aead,
                        internal::ChaCha20Poly1305ZeroCopyAead(key));
  return std::make_unique<internal::AeadFromZeroCopy>(
      std::move(zero_copy_aead));
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
