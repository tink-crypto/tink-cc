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
///////////////////////////////////////////////////////////////////////////////

#ifndef TINK_KEM_KEM_DECAPSULATE_H_
#define TINK_KEM_KEM_DECAPSULATE_H_

#include "absl/strings/string_view.h"
#include "tink/keyset_handle.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// A KEM decapsulation interface.
//
// The decapsulation method doesn't expose the raw shared secret, but a
// KeysetHandle derived from it.
class KemDecapsulate {
 public:
  // Decapsulates the ciphertext and returns a KeysetHandle derived from the
  // shared secret.
  virtual absl::StatusOr<KeysetHandle> Decapsulate(
      absl::string_view ciphertext) const = 0;

  virtual ~KemDecapsulate() = default;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEM_KEM_DECAPSULATE_H_
