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

#ifndef TINK_HYBRID_HYBRID_DECRYPT_WRAPPER_H_
#define TINK_HYBRID_HYBRID_DECRYPT_WRAPPER_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "tink/hybrid_decrypt.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// Wraps a set of HybridDecrypt-instances that correspond to a keyset,
// and combines them into a single HybridDecrypt-primitive, that for
// actual decryption uses the instance that matches the ciphertext prefix.
class HybridDecryptWrapper
    : public PrimitiveWrapper<HybridDecrypt, HybridDecrypt> {
 public:
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> Wrap(
      std::unique_ptr<PrimitiveSet<HybridDecrypt>> primitive_set)
      const override;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_HYBRID_DECRYPT_WRAPPER_H_
