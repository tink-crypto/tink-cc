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

#ifndef TINK_UTIL_VALIDATION_H_
#define TINK_UTIL_VALIDATION_H_

#include <cstdint>

#include "tink/util/status.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// Various validation helpers.

absl::Status ValidateAesKeySize(uint32_t key_size);

absl::Status ValidateKey(const google::crypto::tink::Keyset::Key& key);

absl::Status ValidateKeyset(const google::crypto::tink::Keyset& keyset);

absl::Status ValidateVersion(uint32_t candidate, uint32_t max_expected);

}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_VALIDATION_H_
