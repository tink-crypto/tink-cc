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

#ifndef TINK_SUBTLE_RANDOM_H_
#define TINK_SUBTLE_RANDOM_H_

#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/types/span.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {

// Utility class for generating random numbers.
class Random {
 public:
  // Fills the given `buffer` with random bytes.
  //
  // Random bytes generation uses the `RAND_bytes` function from
  // BoringSSL/OpenSSL. Returns an error if the underlying random number
  // generator fails.
  //
  // BoringSSL RAND_bytes always returns 1. In case of insufficient entropy at
  // the time of the call, BoringSSL's RAND_bytes will behave in different ways
  // depending on the operating system, version, and FIPS mode. For Linux with a
  // semi-recent kernel, it will block until the system has collected at least
  // 128 bits since boot. For old kernels without getrandom support (and not in
  // FIPS mode), it will resort to /dev/urandom.
  //
  // OpenSSL RAND_bytes may fail as documented in
  // https://www.openssl.org/docs/man1.1.1/man3/RAND_bytes.html ("1 on success,
  // -1 if not supported by the current RAND method, or 0 on other failure").
  static absl::Status GetRandomBytes(absl::Span<char> buffer);
  // Returns a random string of desired length.
  //
  // This and the methods below crash if the underlying random number generator
  // fails.
  static std::string GetRandomBytes(size_t length);
  static uint32_t GetRandomUInt32();
  static uint16_t GetRandomUInt16();
  static uint8_t GetRandomUInt8();
  // Returns length bytes of random data stored in specialized key container.
  static SecretData GetRandomKeyBytes(size_t length);
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_RANDOM_H_
