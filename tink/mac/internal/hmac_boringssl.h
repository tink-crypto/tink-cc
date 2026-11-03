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

#ifndef TINK_MAC_INTERNAL_HMAC_BORINGSSL_H_
#define TINK_MAC_INTERNAL_HMAC_BORINGSSL_H_

#include <cstdint>
#include <memory>

#include "absl/status/statusor.h"
#include "tink/mac.h"
#include "tink/mac/hmac_key.h"
#include "tink/secret_data.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<Mac>> NewHmacBoringSsl(const HmacKey& key);

// Overload used only by the legacy `subtle::HmacBoringSsl` class.
// TODO(b/571437401): Remove this overload along with `subtle::HmacBoringSsl`.
absl::StatusOr<std::unique_ptr<Mac>> NewHmacBoringSsl(
    subtle::HashType hash_type, uint32_t tag_size, SecretData key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_INTERNAL_HMAC_BORINGSSL_H_
