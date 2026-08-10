// Copyright 2022 Google LLC
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

#ifndef TINK_SIGNATURE_INTERNAL_PREHASH_FORMAT_H_
#define TINK_SIGNATURE_INTERNAL_PREHASH_FORMAT_H_

#include <cstdint>
#include <string>

#include "absl/types/optional.h"

namespace crypto {
namespace tink {
namespace internal {

// Prehash prefix starts with 0xff byte.
constexpr uint8_t kPrehashStartByte = 0xff;

// Prehash prefix has start byte followed by a 4-byte key id.
constexpr int kPrehashPrefixSize = 5;

// Returns prehash prefix {`kPrehashStartByte` || `key_id` (big endian)}.
// Every prehash will have the same output prefix (regardless of the key type).
// If `id_requirement` is nullopt, returns an empty string.
std::string GetPrehashPrefix(absl::optional<int32_t> id_requirement);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_PREHASH_FORMAT_H_
