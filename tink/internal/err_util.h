// Copyright 2021 Google LLC
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
#ifndef TINK_INTERNAL_ERR_UTIL_H_
#define TINK_INTERNAL_ERR_UTIL_H_

#include <cstddef>
#include <string>

#include "openssl/err.h"

namespace crypto {
namespace tink {
namespace internal {

// Returns OpenSSL error strings accumulated in the error queue, thus emptying
// the queue.
//
// Must be called by the same library (ideally same compilation unit) that made
// the BoringSSL call causing the error.
//
// Function is static inline because `ERR_print_errors_cb` might resolve to
// different functions in different compilation units, and it must always be
// resolved to the same the caller would get if they were to call it directly.
static inline std::string GetSslErrors() {
  std::string ret;
  ERR_print_errors_cb(
      [](const char *str, size_t len, void *ctx) -> int {
        static_cast<std::string *>(ctx)->append(str, len);
        return 1;
      },
      &ret);
  return ret;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_ERR_UTIL_H_
