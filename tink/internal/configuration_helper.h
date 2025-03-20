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

#ifndef TINK_INTERNAL_CONFIGURATION_HELPER_H_
#define TINK_INTERNAL_CONFIGURATION_HELPER_H_

#include <memory>
#include <tuple>
#include <typeindex>

#include "absl/container/flat_hash_map.h"
#include "absl/functional/any_invocable.h"
#include "absl/status/statusor.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

template <class P, class K>
using PrimitiveGetterFn =
    absl::AnyInvocable<absl::StatusOr<std::unique_ptr<P>>(const K&) const>;

// A type-erased form of `PrimitiveGetterFn`, with `void*` replacing
// references/unique pointers to specific types.
using TypeErasedPrimitiveGetterFn =
    absl::AnyInvocable<absl::StatusOr<void*>(const void*) const>;

// Stores a TypeErasedPrimitiveGetterFn for each given (Primitive, Key) pair.
using PrimitiveGetterFnMap =
    absl::flat_hash_map<std::tuple<std::type_index, std::type_index>,
                        TypeErasedPrimitiveGetterFn>;

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_CONFIGURATION_HELPER_H_
