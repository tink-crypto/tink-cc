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

#ifndef TINK_KEM_INTERNAL_KEM_DECAPSULATE_WRAPPER_H_
#define TINK_KEM_INTERNAL_KEM_DECAPSULATE_WRAPPER_H_

#include <memory>

#include "tink/kem/kem_decapsulate.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

class KemDecapsulateWrapper
    : public PrimitiveWrapper<KemDecapsulate, KemDecapsulate> {
 public:
  util::StatusOr<std::unique_ptr<KemDecapsulate>> Wrap(
      std::unique_ptr<PrimitiveSet<KemDecapsulate>> primitive_set)
      const override;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEM_INTERNAL_KEM_DECAPSULATE_WRAPPER_H_
