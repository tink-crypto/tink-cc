// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_SIGNATURE_INTERNAL_PREHASH_WRAPPER_H_
#define TINK_SIGNATURE_INTERNAL_PREHASH_WRAPPER_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/signature/prehash.h"

namespace crypto {
namespace tink {
namespace internal {

// Wraps a set of `Prehash` instances that correspond to a keyset into a single
// `Prehash` primitive that is used for generating precomputed hashes.
class PrehashWrapper : public PrimitiveWrapper<Prehash, Prehash> {
 public:
  // Returns a Prehash primitive that uses the primary Prehash instance from
  // `primitive_set`, which must be non-null (and must contain a primary).
  absl::StatusOr<std::unique_ptr<Prehash>> Wrap(
      std::unique_ptr<PrimitiveSet<Prehash>> primitive_set) const override;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_PREHASH_WRAPPER_H_
