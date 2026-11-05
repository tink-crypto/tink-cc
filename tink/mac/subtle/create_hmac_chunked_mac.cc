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

#include "tink/mac/subtle/create_hmac_chunked_mac.h"

#include <memory>

#include "absl/status/statusor.h"
#include "tink/chunked_mac.h"
#include "tink/mac/hmac_key.h"
#include "tink/mac/internal/chunked_mac_impl.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<std::unique_ptr<ChunkedMac>> CreateHmacChunkedMac(
    const HmacKey& key) {
  return internal::NewChunkedHmac(key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
