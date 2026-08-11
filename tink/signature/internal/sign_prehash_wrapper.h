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

#ifndef TINK_SIGNATURE_INTERNAL_SIGN_PREHASH_WRAPPER_H_
#define TINK_SIGNATURE_INTERNAL_SIGN_PREHASH_WRAPPER_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/internal/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/signature/sign_prehash.h"

namespace crypto {
namespace tink {
namespace internal {

// Wraps a set of `SignPrehash` instances that correspond to a keyset into a
// single `SignPrehash` primitive. The actual signing operation will use the
// instance that matches the prehash prefix.
class SignPrehashWrapper : public PrimitiveWrapper<SignPrehash, SignPrehash> {
 public:
  // Returns a `SignPrehash` primitive that uses the `SignPrehash` instance
  // from `primitive_set` that corresponds to the prehash prefix. Must be
  // non-null and must contain a primary instance.
  absl::StatusOr<std::unique_ptr<SignPrehash>> Wrap(
      std::unique_ptr<PrimitiveSet<SignPrehash>> primitive_set) const override;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_SIGN_PREHASH_WRAPPER_H_
