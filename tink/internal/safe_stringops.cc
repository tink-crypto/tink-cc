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

#include "tink/internal/safe_stringops.h"

#include <cstddef>

#include "openssl/mem.h"
#include "tink/internal/call_with_core_dump_protection.h"

namespace crypto {
namespace tink {
namespace internal {

bool SafeCryptoMemEquals(const void* s1, const void* s2, size_t n) {
  return CallWithCoreDumpProtection(
      [s1, s2, n]() { return CRYPTO_memcmp(s1, s2, n) == 0; });
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
