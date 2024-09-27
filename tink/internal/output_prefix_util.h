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

#ifndef TINK_INTERNAL_OUTPUT_PREFIX_UTIL_H_
#define TINK_INTERNAL_OUTPUT_PREFIX_UTIL_H_

#include <cstdint>
#include <string>

namespace crypto {
namespace tink {
namespace internal {

// Returns the output prefix from the given `prefix_byte` and `id`.
//
// The result is encoded as a 5-byte string with `prefix_byte` as the first
// byte, and the remaining bytes are the `id` encoded as a big endian.
inline std::string ComputeOutputPrefix(uint8_t prefix_byte, int id) {
  std::string output_prefix;
  output_prefix.resize(5);
  output_prefix[0] = prefix_byte;
  output_prefix[1] = (id >> 24) & 0xff;
  output_prefix[2] = (id >> 16) & 0xff;
  output_prefix[3] = (id >> 8) & 0xff;
  output_prefix[4] = id & 0xff;
  return output_prefix;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_OUTPUT_PREFIX_UTIL_H_
