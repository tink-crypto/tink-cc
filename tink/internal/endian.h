// Copyright 2025 Google LLC
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

#ifndef TINK_INTERNAL_ENDIAN_H_
#define TINK_INTERNAL_ENDIAN_H_

#include <cstdint>

namespace crypto {
namespace tink {
namespace internal {

// Loads a big-endian byte array into an integer.
inline uint32_t LoadBigEndian32(const uint8_t* data) {
  return (static_cast<uint32_t>(data[0]) << 24) |
         (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) |
         (static_cast<uint32_t>(data[3]));
}

// Stores an integer into a big-endian byte array.
inline void StoreBigEndian32(uint8_t* out, uint32_t value) {
  out[0] = 0xff & (value >> 24);
  out[1] = 0xff & (value >> 16);
  out[2] = 0xff & (value >> 8);
  out[3] = 0xff & (value >> 0);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_ENDIAN_H_
