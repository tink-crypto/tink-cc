// Copyright 2017 Google Inc.
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

#include "tink/subtle/hmac_boringssl.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/status/statusor.h"
#include "tink/mac.h"
#include "tink/mac/internal/hmac_boringssl.h"
#include "tink/secret_data.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<std::unique_ptr<Mac>> HmacBoringSsl::New(HashType hash_type,
                                                        uint32_t tag_size,
                                                        SecretData key_value) {
  return internal::NewHmacBoringSsl(hash_type, tag_size, std::move(key_value));
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
