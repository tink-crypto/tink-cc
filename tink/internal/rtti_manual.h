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

#ifndef TINK_INTERNAL_RTTI_MANUAL_H_
#define TINK_INTERNAL_RTTI_MANUAL_H_

// IWYU pragma: private, include "third_party/tink/cc/internal/rtti.h"

#if defined(TINK_USE_CUSTOM_RTTI)

#include <cstdint>
#include <string>
#include <type_traits>
#include <utility>

namespace crypto {
namespace tink {
namespace internal {

// Lightweight, hashable, comparable value type identifying a C++ type without
// compiler RTTI, analogous to `std::type_index`.
//
// Wraps a 64-bit unsigned integer type ID (`0` when default-constructed; all
// valid registered type IDs are strictly non-zero). Supports equality (`==`,
// `!=`), strict weak ordering (`<`), and Abseil hashing (`AbslHashValue`) for
// use as a key in ordered or unordered associative containers.
class TypeIndex {
 public:
  constexpr TypeIndex() = default;
  constexpr explicit TypeIndex(std::uint64_t id) : id_(id) {}

  // Returns a string representation of the underlying numeric type ID for
  // diagnostics and logging. Callers must not depend on a specific format.
  std::string name() const { return std::to_string(id_); }

  friend constexpr bool operator==(TypeIndex lhs, TypeIndex rhs) {
    return lhs.id_ == rhs.id_;
  }
  friend constexpr bool operator!=(TypeIndex lhs, TypeIndex rhs) {
    return lhs.id_ != rhs.id_;
  }
  friend constexpr bool operator<(TypeIndex lhs, TypeIndex rhs) {
    return lhs.id_ < rhs.id_;
  }

  template <typename H>
  friend H AbslHashValue(H h, TypeIndex index) {
    return H::combine(std::move(h), index.id_);
  }

 private:
  std::uint64_t id_ = 0;
};

// Befriended by all `TINK_RTTI_*` macros so RTTI members can remain `private:`
// on user classes. Also centralizes compile-time trait and ID validation.
struct RttiAccess {
  // Evaluates to `std::true_type` iff `T` itself (not merely an ancestor of
  // `T`) declares `TINK_RTTI_ADD_METHODS_BASE` or
  // `TINK_RTTI_ADD_METHODS_DERIVED`. If `T` only inherits
  // `GetTinkRttiTypeIndex` from a `Base`, `&T::GetTinkRttiTypeIndex` has type
  // `TypeIndex (Base::*)() const`, which does not match
  // `TypeIndex (T::*)() const`.
  template <typename T>
  static auto HasRttiMethodsHelper(int)
      -> std::is_same<decltype(&T::GetTinkRttiTypeIndex),
                      TypeIndex (T::*)() const>;
  template <typename T>
  static std::false_type HasRttiMethodsHelper(...);

  template <typename T>
  using HasRttiMethods = decltype(HasRttiMethodsHelper<T>(0));

  // Evaluates to `std::true_type` iff `T` itself (not merely an ancestor of
  // `T`) declares `TINK_RTTI_SET_TYPE_ID` or `TINK_RTTI_COMPUTE_TYPE_ID`, using
  // the same member-pointer exact-class check as `HasRttiMethods`.
  template <typename T>
  static auto HasTypeIdHelper(int) -> std::is_same<
      decltype(&T::TinkRttiTypeIdTag),
      void (T::*)(std::integral_constant<std::uint64_t, T::kTinkRttiTypeId>)
          const>;
  template <typename T>
  static std::false_type HasTypeIdHelper(...);

  template <typename T>
  using HasTypeId = decltype(HasTypeIdHelper<T>(0));

  // Validates at compile time that `Id` fits in a non-zero 16-bit unsigned
  // integer (`[1, 65535]`). `0` is reserved so default-constructed `TypeIndex`
  // never matches a registered type and unused 16-bit parameter slots in
  // `ComputeTypeId` cannot alias lower-arity templates.
  template <std::int64_t Id>
  static constexpr std::uint64_t Validate16BitId() {
    static_assert(Id > 0 && Id <= 0xFFFF,
                  "Tink RTTI 16-bit type ID must be in [1, 65535].");
    return static_cast<std::uint64_t>(Id);
  }

  // Extracts the 16-bit type ID of a template argument `T` passed to
  // `TINK_RTTI_COMPUTE_TYPE_ID`. Rejects unannotated types as well as types
  // whose ID was itself produced by `TINK_RTTI_COMPUTE_TYPE_ID` (> 16 bits).
  template <typename T>
  static constexpr std::uint64_t Get16BitTypeId() {
    using CleanT = std::remove_cv_t<std::remove_reference_t<T>>;
    static_assert(HasTypeId<CleanT>::value,
                  "Template parameter in TINK_RTTI_COMPUTE_TYPE_ID must "
                  "declare TINK_RTTI_SET_TYPE_ID.");
    if constexpr (HasTypeId<CleanT>::value) {
      static_assert(
          CleanT::kTinkRttiTypeId > 0 && CleanT::kTinkRttiTypeId <= 0xFFFF,
          "Template parameter in TINK_RTTI_COMPUTE_TYPE_ID must have a 16-bit "
          "type ID (declared via TINK_RTTI_SET_TYPE_ID).");
      return CleanT::kTinkRttiTypeId;
    } else {
      return 0;
    }
  }

  // Packs `BaseId` (bits `[15:0]`) and 1 to 3 template-parameter 16-bit IDs
  // (bits `[31:16]`, `[47:32]`, `[63:48]`) into a single 64-bit type ID.
  template <std::int64_t BaseId, typename... Params>
  static constexpr std::uint64_t ComputeTypeId() {
    static_assert(
        sizeof...(Params) >= 1 && sizeof...(Params) <= 3,
        "TINK_RTTI_COMPUTE_TYPE_ID supports 1 to 3 template parameters.");
    std::uint64_t result = Validate16BitId<BaseId>();
    if constexpr (sizeof...(Params) >= 1 && sizeof...(Params) <= 3) {
      const std::uint64_t param_ids[] = {Get16BitTypeId<Params>()...};
      int shift = 16;
      for (std::uint64_t param_id : param_ids) {
        result |= (param_id << shift);
        shift += 16;
      }
    }
    return result;
  }

  template <typename T>
  static constexpr TypeIndex GetStaticTypeIndex() {
    return TypeIndex(T::kTinkRttiTypeId);
  }

  template <typename T>
  static TypeIndex GetDynamicTypeIndex(const T& object) {
    return object.GetTinkRttiTypeIndex();
  }
};

// Returns the compile-time `TypeIndex` for `T`, ignoring top-level
// cv-qualifiers and references (analogous to `std::type_index(typeid(T))`).
//
// `T` itself (not merely a base class of `T`) must declare
// `TINK_RTTI_SET_TYPE_ID` or `TINK_RTTI_COMPUTE_TYPE_ID`. `T` does not need to
// be polymorphic or declare `TINK_RTTI_ADD_METHODS_*` for static lookup.
template <typename T>
constexpr TypeIndex GetTypeIndex() {
  using CleanT = std::remove_cv_t<std::remove_reference_t<T>>;
  static_assert(RttiAccess::HasTypeId<CleanT>::value,
                "GetTypeIndex<T>() requires T to declare "
                "TINK_RTTI_SET_TYPE_ID or TINK_RTTI_COMPUTE_TYPE_ID.");
  if constexpr (RttiAccess::HasTypeId<CleanT>::value) {
    return RttiAccess::GetStaticTypeIndex<CleanT>();
  } else {
    return TypeIndex();
  }
}

// Returns the dynamic `TypeIndex` of `object`'s runtime type via virtual
// dispatch (analogous to `std::type_index(typeid(object))`).
//
// `object` must be passed by reference (passing a pointer fails at compile
// time; dereference with `*ptr`), and `object`'s static type `T` must declare
// both a methods macro (`TINK_RTTI_ADD_METHODS_BASE` or
// `TINK_RTTI_ADD_METHODS_DERIVED`) and a type-ID macro (`TINK_RTTI_SET_TYPE_ID`
// or `TINK_RTTI_COMPUTE_TYPE_ID`).
template <typename T>
TypeIndex GetTypeIndex(const T& object) {
  static_assert(!std::is_pointer_v<T>,
                "Pass a reference (*ptr) to GetTypeIndex, not a pointer.");
  if constexpr (!std::is_pointer_v<T>) {
    using CleanT = std::remove_cv_t<std::remove_reference_t<T>>;
    static_assert(
        RttiAccess::HasRttiMethods<CleanT>::value,
        "GetTypeIndex(object) requires object's static type to declare "
        "TINK_RTTI_ADD_METHODS_BASE or TINK_RTTI_ADD_METHODS_DERIVED.");
    static_assert(
        RttiAccess::HasTypeId<CleanT>::value,
        "GetTypeIndex(object) requires object's static type to declare "
        "TINK_RTTI_SET_TYPE_ID or TINK_RTTI_COMPUTE_TYPE_ID.");
    if constexpr (RttiAccess::HasRttiMethods<CleanT>::value &&
                  RttiAccess::HasTypeId<CleanT>::value) {
      return RttiAccess::GetDynamicTypeIndex(object);
    }
  }
  return TypeIndex();
}

// Declares the root virtual RTTI dispatch methods on a polymorphic base class.
//
// Place in the `private:` section of a root base class alongside
// `TINK_RTTI_SET_TYPE_ID` or `TINK_RTTI_COMPUTE_TYPE_ID` (macro ordering within
// the class does not matter). The enclosing class should also declare a
// `virtual` destructor. Subclasses of an RTTI-enabled base class must use
// `TINK_RTTI_ADD_METHODS_DERIVED(DirectBase)` rather than this macro.
#define TINK_RTTI_ADD_METHODS_BASE()                                      \
  friend struct ::crypto::tink::internal::RttiAccess;                     \
  using TinkRttiBaseType = void;                                          \
  virtual ::crypto::tink::internal::TypeIndex GetTinkRttiTypeIndex()      \
      const {                                                             \
    using Self = std::remove_cv_t<std::remove_pointer_t<decltype(this)>>; \
    return ::crypto::tink::internal::GetTypeIndex<Self>();                \
  }

// Overrides the virtual RTTI dispatch methods on a subclass of an RTTI-enabled
// direct base class `BaseClass`.
//
// Place in the `private:` section of the derived class alongside
// `TINK_RTTI_SET_TYPE_ID` or `TINK_RTTI_COMPUTE_TYPE_ID`. If `BaseClass` is a
// multi-parameter template containing commas, alias it first with `using`.
//
// Verifies at compile time that `BaseClass` is a strict base of the enclosing
// class and itself declares `TINK_RTTI_ADD_METHODS_BASE` or
// `TINK_RTTI_ADD_METHODS_DERIVED`.
#define TINK_RTTI_ADD_METHODS_DERIVED(BaseClass)                          \
  friend struct ::crypto::tink::internal::RttiAccess;                     \
  ::crypto::tink::internal::TypeIndex GetTinkRttiTypeIndex()              \
      const override {                                                    \
    using Self = std::remove_cv_t<std::remove_pointer_t<decltype(this)>>; \
    static_assert(std::is_base_of_v<BaseClass, Self> &&                   \
                      !std::is_same_v<BaseClass, Self>,                   \
                  "Invalid BaseClass in TINK_RTTI_ADD_METHODS_DERIVED."); \
    static_assert(                                                        \
        ::crypto::tink::internal::RttiAccess::HasRttiMethods<             \
            BaseClass>::value,                                            \
        "BaseClass must declare TINK_RTTI_ADD_METHODS_BASE or "           \
        "TINK_RTTI_ADD_METHODS_DERIVED.");                                \
    return ::crypto::tink::internal::GetTypeIndex<Self>();                \
  }

// Assigns a static 16-bit integer type ID (`id` in `[1, 65535]`) to a
// non-templated class or struct. IDs in `[1, 32767]` are reserved for Tink's
// built-in types; external user-defined subclasses should choose IDs in
// `[32768, 65535]`.
//
// Place in the `private:` section of classes or structs that are queried with
// `GetTypeIndex<T>()` or passed as template parameters to
// `TINK_RTTI_COMPUTE_TYPE_ID`.
#define TINK_RTTI_SET_TYPE_ID(id)                                    \
  friend struct ::crypto::tink::internal::RttiAccess;                \
  static constexpr std::uint64_t kTinkRttiTypeId =                   \
      ::crypto::tink::internal::RttiAccess::Validate16BitId<(id)>(); \
  void TinkRttiTypeIdTag(                                            \
      std::integral_constant<std::uint64_t, kTinkRttiTypeId>) const

// Computes a static 64-bit integer type ID for a class template by packing the
// template's own 16-bit `id` (in `[1, 65535]`, bits `[15:0]`; `[1, 32767]`
// reserved for Tink's built-in templates and `[32768, 65535]` available for
// external user-defined templates) with the 16-bit type IDs of 1 to 3 type
// template parameters (`P0` in bits `[31:16]`, optional `P1` in bits `[47:32]`,
// optional `P2` in bits `[63:48]`).
//
// Each template parameter passed in `...` must declare a 16-bit type ID via
// `TINK_RTTI_SET_TYPE_ID` (nested `TINK_RTTI_COMPUTE_TYPE_ID` arguments are
// rejected at compile time because their IDs exceed 16 bits). Because all
// valid 16-bit IDs are strictly non-zero, computed IDs for 0-, 1-, 2-, and
// 3-parameter types occupy disjoint bit patterns and never alias across
// different template arities.
#define TINK_RTTI_COMPUTE_TYPE_ID(id, ...)                                \
  friend struct ::crypto::tink::internal::RttiAccess;                     \
  static constexpr std::uint64_t kTinkRttiTypeId =                        \
      ::crypto::tink::internal::RttiAccess::ComputeTypeId<(id),           \
                                                          __VA_ARGS__>(); \
  void TinkRttiTypeIdTag(                                                 \
      std::integral_constant<std::uint64_t, kTinkRttiTypeId>) const

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // defined(TINK_USE_CUSTOM_RTTI)

#endif  // TINK_INTERNAL_RTTI_MANUAL_H_
