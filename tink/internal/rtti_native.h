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

#ifndef TINK_INTERNAL_RTTI_NATIVE_H_
#define TINK_INTERNAL_RTTI_NATIVE_H_

// IWYU pragma: private, include "third_party/tink/cc/internal/rtti.h"

#if !defined(TINK_USE_CUSTOM_RTTI)

#include <cstdlib>
#include <type_traits>
#include <typeindex>
#include <typeinfo>

namespace crypto {
namespace tink {
namespace internal {

// Hashable, comparable value type identifying a C++ type, backed directly by
// `std::type_index` when `TINK_USE_CUSTOM_RTTI` is not defined.
using TypeIndex = std::type_index;

// Returns the compile-time `TypeIndex` for `T`, ignoring top-level
// cv-qualifiers and references (wraps `std::type_index(typeid(T))`).
template <typename T>
TypeIndex GetTypeIndex() {
#if defined(__cpp_rtti) || defined(__GXX_RTTI) || defined(_CPPRTTI)
  return std::type_index(typeid(T));
#else
  static_assert(sizeof(T) == 0,
                "GetTypeIndex requires -frtti or TINK_USE_CUSTOM_RTTI.");
  std::abort();
#endif
}

// Returns the dynamic `TypeIndex` of `object`'s runtime type (wraps
// `std::type_index(typeid(object))`).
//
// Passing a pointer fails at compile time in both standard and custom RTTI
// modes so callers dereference first (`*ptr`) rather than accidentally querying
// the static pointer type `T*`.
template <typename T>
TypeIndex GetTypeIndex(const T& object) {
  static_assert(!std::is_pointer_v<T>,
                "Pass a reference (*ptr) to GetTypeIndex, not a pointer.");
#if defined(__cpp_rtti) || defined(__GXX_RTTI) || defined(_CPPRTTI)
  return std::type_index(typeid(object));
#else
  (void)object;
  static_assert(sizeof(T) == 0,
                "GetTypeIndex requires -frtti or TINK_USE_CUSTOM_RTTI.");
  std::abort();
#endif
}

// Downcasts pointer `from` to pointer type `To` via `dynamic_cast<To>(from)`,
// returning `nullptr` if `from == nullptr` or if `from`'s runtime object is not
// an instance of `To`.
template <typename To, typename From>
To DynamicCast(From* from) {
#if defined(__cpp_rtti) || defined(__GXX_RTTI) || defined(_CPPRTTI)
  return dynamic_cast<To>(from);
#else
  (void)from;
  static_assert(sizeof(To) == 0,
                "DynamicCast requires -frtti or TINK_USE_CUSTOM_RTTI.");
  return nullptr;
#endif
}

// No-op class-annotation macros in standard C++ RTTI mode (zero vtable or
// object-size overhead). See `rtti.h` and `rtti_manual.h` for their expansion
// and requirements when `TINK_USE_CUSTOM_RTTI` is defined.
#define TINK_RTTI_ADD_METHODS_BASE()
#define TINK_RTTI_ADD_METHODS_DERIVED(BaseClass)
#define TINK_RTTI_SET_TYPE_ID(id)
#define TINK_RTTI_COMPUTE_TYPE_ID(id, ...)

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // !defined(TINK_USE_CUSTOM_RTTI)

#endif  // TINK_INTERNAL_RTTI_NATIVE_H_
