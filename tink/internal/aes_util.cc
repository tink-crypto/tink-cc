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
#include "tink/internal/aes_util.h"

#include <cstdint>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "openssl/evp.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<const EVP_CIPHER *> GetAesCtrCipherForKeySize(
    uint32_t key_size_in_bytes) {
  switch (key_size_in_bytes) {
    case 16:
      return EVP_aes_128_ctr();
    case 32:
      return EVP_aes_256_ctr();
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Invalid key size ", key_size_in_bytes));
  }
}

absl::StatusOr<const EVP_CIPHER *> GetAesCbcCipherForKeySize(
    uint32_t key_size_in_bytes) {
  switch (key_size_in_bytes) {
    case 16:
      return EVP_aes_128_cbc();
    case 32:
      return EVP_aes_256_cbc();
  }
  return absl::Status(absl::StatusCode::kInvalidArgument,
                      absl::StrCat("Invalid key size ", key_size_in_bytes));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
