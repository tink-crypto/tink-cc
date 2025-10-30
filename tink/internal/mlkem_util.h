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

#ifndef TINK_INTERNAL_MLKEM_UTIL_H_
#define TINK_INTERNAL_MLKEM_UTIL_H_

#include <stdint.h>

#include <string>

#include "absl/status/statusor.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

enum MlKemKeySize {
  ML_KEM_UNKNOWN_SIZE = 0,
  ML_KEM768 = 1,
  ML_KEM1024 = 2,
};

struct MlKemKey {
  std::string public_key;
  SecretData private_key;
};

// Returns a new MlKemKey key. It returns a kInternal error status if the
// OpenSSL/BoringSSL APIs fail.
absl::StatusOr<MlKemKey> NewMlKemKey(MlKemKeySize key_size);

// Returns a MlKemKey matching the specified private key. It returns a kInternal
// error status if the OpenSSL/BoringSSL APIs fail or if the private key is
// invalid.
absl::StatusOr<MlKemKey> MlKemKeyFromPrivateKey(const SecretData& private_key,
                                                MlKemKeySize key_size);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_MLKEM_UTIL_H_
