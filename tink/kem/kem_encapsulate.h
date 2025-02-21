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

#ifndef TINK_KEM_KEM_ENCAPSULATE_H_
#define TINK_KEM_KEM_ENCAPSULATE_H_

#include <string>

#include "tink/keyset_handle.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// A KEM encapsulation.
//
// This doesn't expose the raw shared secret, but a KeysetHandle derived from
// it.
struct KemEncapsulation {
  // Ciphertext, to send to the recipient who can decapsulate it.
  std::string ciphertext;
  // KeysetHandle derived from the shared secret.
  KeysetHandle keyset_handle;
};

// A KEM encapsulation interface.
//
// The encapsulation method doesn't expose the raw shared secret, but a
// KeysetHandle derived from it.
class KemEncapsulate {
 public:
  // Generates a new encapsulation, containing the ciphertext and a KeysetHandle
  // derived from the shared secret.
  virtual absl::StatusOr<KemEncapsulation> Encapsulate() const = 0;

  virtual ~KemEncapsulate() = default;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEM_KEM_ENCAPSULATE_H_
