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

// Non-compilation tests for Tink RTTI macros and utilities with `-fno-rtti`
// (both with and without `-DTINK_USE_CUSTOM_RTTI`).

#include "tink/internal/rtti.h"

#include <typeinfo>

namespace crypto {
namespace tink {
namespace internal {
namespace {

// -----------------------------------------------------------------------------
// Valid baseline types used across negative test cases
// -----------------------------------------------------------------------------

// Alias macros so check_rtti_type_ids.sh ignores negative-compilation test IDs.
#define TEST_RTTI_SET_TYPE_ID TINK_RTTI_SET_TYPE_ID
#define TEST_RTTI_COMPUTE_TYPE_ID TINK_RTTI_COMPUTE_TYPE_ID

struct Tag1 {
  TEST_RTTI_SET_TYPE_ID(1);
};
struct Tag2 {
  TEST_RTTI_SET_TYPE_ID(2);
};
struct Tag3 {
  TEST_RTTI_SET_TYPE_ID(3);
};
struct Tag4 {
  TEST_RTTI_SET_TYPE_ID(4);
};

class ValidBase {
 public:
  virtual ~ValidBase() = default;

 private:
  TINK_RTTI_ADD_METHODS_BASE();
  TEST_RTTI_SET_TYPE_ID(10);
};

class ValidMiddle : public ValidBase {
 private:
  TINK_RTTI_ADD_METHODS_DERIVED(ValidBase);
  TEST_RTTI_SET_TYPE_ID(11);
};

class ValidLeaf : public ValidMiddle {
 private:
  TINK_RTTI_ADD_METHODS_DERIVED(ValidMiddle);
  TEST_RTTI_SET_TYPE_ID(12);
};

class ValidSibling : public ValidBase {
 private:
  TINK_RTTI_ADD_METHODS_DERIVED(ValidBase);
  TEST_RTTI_SET_TYPE_ID(13);
};

class OtherRoot {
 public:
  virtual ~OtherRoot() = default;

 private:
  TINK_RTTI_ADD_METHODS_BASE();
  TEST_RTTI_SET_TYPE_ID(14);
};

template <typename T>
class ValidTemplate {
 public:
  virtual ~ValidTemplate() = default;

 private:
  TINK_RTTI_ADD_METHODS_BASE();
  TEST_RTTI_COMPUTE_TYPE_ID(15, T);
};

#if defined(TINK_USE_CUSTOM_RTTI)

// -----------------------------------------------------------------------------
// 1. Type ID range checks
// -----------------------------------------------------------------------------

namespace test_zero_type_id {
struct ZeroId {
  // expected-error@rtti_manual.h:* {{16-bit type ID must be in [1, 65535]}}
  TEST_RTTI_SET_TYPE_ID(0);
};
}  // namespace test_zero_type_id

namespace test_negative_type_id {
struct NegativeId {
  // expected-error@rtti_manual.h:* {{16-bit type ID must be in [1, 65535]}}
  TEST_RTTI_SET_TYPE_ID(-7);
};
}  // namespace test_negative_type_id

namespace test_overflow_16bit_type_id {
struct TooLargeId {
  // expected-error@rtti_manual.h:* {{16-bit type ID must be in [1, 65535]}}
  TEST_RTTI_SET_TYPE_ID(65536);
};
}  // namespace test_overflow_16bit_type_id

// -----------------------------------------------------------------------------
// 2. TINK_RTTI_COMPUTE_TYPE_ID template parameter validation
// -----------------------------------------------------------------------------

namespace test_compute_type_id_unannotated_param {
struct UnannotatedParam {};
template <typename T>
struct BadTemplate {
  // expected-error-re@rtti_manual.h:* {{Template parameter{{.*}}SET_TYPE_ID}}
  TEST_RTTI_COMPUTE_TYPE_ID(110, T);
};
[[maybe_unused]] BadTemplate<UnannotatedParam> instance;
}  // namespace test_compute_type_id_unannotated_param

namespace test_compute_type_id_nested_computed_param {
template <typename T>
struct OuterTemplate {
  // expected-error@rtti_manual.h:* {{must have a 16-bit type ID}}
  TEST_RTTI_COMPUTE_TYPE_ID(111, T);
};
[[maybe_unused]] OuterTemplate<ValidTemplate<Tag1>> instance;
}  // namespace test_compute_type_id_nested_computed_param

namespace test_compute_type_id_too_many_params {
template <typename A, typename B, typename C, typename D>
struct FourParamTemplate {
  // expected-error@rtti_manual.h:* {{supports 1 to 3 template parameters}}
  TEST_RTTI_COMPUTE_TYPE_ID(112, A, B, C, D);
};
[[maybe_unused]] FourParamTemplate<Tag1, Tag2, Tag3, Tag4> instance;
}  // namespace test_compute_type_id_too_many_params

// -----------------------------------------------------------------------------
// 3. Class hierarchy and macro pairing checks
// -----------------------------------------------------------------------------

namespace test_methods_without_type_id {
class MethodsOnlyBase {
 public:
  virtual ~MethodsOnlyBase() = default;

 private:
  // Defining RTTI methods on a non-template class without a type-ID macro fails
  // immediately when instantiating GetTinkRttiTypeIndex() / IsTinkRttiInstance.
  // expected-error@rtti_manual.h:* {{GetTypeIndex<T>() requires T to declare}}
  TINK_RTTI_ADD_METHODS_BASE();
};
}  // namespace test_methods_without_type_id

namespace test_derived_macro_with_non_base {
class NotDerivedFromOtherRoot : public ValidBase {
 private:
  // expected-error@+1 {{Invalid BaseClass in TINK_RTTI_ADD_METHODS_DERIVED}}
  TINK_RTTI_ADD_METHODS_DERIVED(OtherRoot);
  TEST_RTTI_SET_TYPE_ID(120);
};
}  // namespace test_derived_macro_with_non_base

namespace test_derived_macro_with_self_as_base {
class SelfAsBase : public ValidBase {
 private:
  // expected-error@+1 {{Invalid BaseClass in TINK_RTTI_ADD_METHODS_DERIVED}}
  TINK_RTTI_ADD_METHODS_DERIVED(SelfAsBase);
  TEST_RTTI_SET_TYPE_ID(121);
};
}  // namespace test_derived_macro_with_self_as_base

namespace test_derived_macro_with_unannotated_base {
class UnannotatedPolymorphicBase {
 public:
  virtual ~UnannotatedPolymorphicBase() = default;
};
class DerivedFromUnannotated : public UnannotatedPolymorphicBase {
 private:
  // expected-error@+2 2 {{only virtual member functions can be marked}}
  // expected-error@+1 {{BaseClass must declare TINK_RTTI_ADD_METHODS_BASE}}
  TINK_RTTI_ADD_METHODS_DERIVED(UnannotatedPolymorphicBase);
  TEST_RTTI_SET_TYPE_ID(122);
};
}  // namespace test_derived_macro_with_unannotated_base

namespace test_subclass_does_not_silently_inherit_annotations {
// Inherits from annotated ValidBase, but forgets both TINK_RTTI_* macros!
class UnannotatedSubclass : public ValidBase {};

// Inherits from annotated ValidBase, declares SET_TYPE_ID, forgets DERIVED!
class SubclassMissingMethods : public ValidBase {
 private:
  TEST_RTTI_SET_TYPE_ID(123);
};

[[maybe_unused]] void TestForgottenSubclassMacros(
    const ValidBase* base_ptr, const SubclassMissingMethods& missing_methods) {
  // expected-error@rtti_manual.h:* {{GetTypeIndex<T>() requires T to declare}}
  (void)GetTypeIndex<UnannotatedSubclass>();

  // expected-error@rtti_manual.h:* {{Source and target types of DynamicCast}}
  (void)DynamicCast<const UnannotatedSubclass*>(base_ptr);

  // expected-error-re@rtti_manual.h:* {{GetTypeIndex(object){{.*}}ADD_METHODS}}
  (void)GetTypeIndex(missing_methods);

  // expected-error@rtti_manual.h:* {{Source and target types of DynamicCast}}
  (void)DynamicCast<const SubclassMissingMethods*>(base_ptr);
}
}  // namespace test_subclass_does_not_silently_inherit_annotations

// -----------------------------------------------------------------------------
// 4. GetTypeIndex and DynamicCast call-site contract checks
// -----------------------------------------------------------------------------

namespace test_call_site_errors {
struct UnannotatedStruct {};

class VirtualDerived : public virtual ValidBase {
 private:
  TINK_RTTI_ADD_METHODS_DERIVED(ValidBase);
  TEST_RTTI_SET_TYPE_ID(130);
};

[[maybe_unused]] void TestGetTypeIndexErrors(const ValidBase* base_ptr,
                                             const Tag1& tag_without_methods,
                                             const UnannotatedStruct& plain) {
  // expected-error@rtti_manual.h:* {{GetTypeIndex<T>() requires T to declare}}
  (void)GetTypeIndex<UnannotatedStruct>();

  // expected-error@rtti_manual.h:* {{Pass a reference (*ptr) to GetTypeIndex}}
  (void)GetTypeIndex(base_ptr);

  // Tag1 has TEST_RTTI_SET_TYPE_ID(1), so GetTypeIndex<Tag1>() is valid, but
  // dynamic GetTypeIndex(tag_without_methods) is rejected because Tag1 is not a
  // polymorphic class with TINK_RTTI_ADD_METHODS_*.
  // expected-error-re@rtti_manual.h:* {{GetTypeIndex(object){{.*}}ADD_METHODS}}
  (void)GetTypeIndex(tag_without_methods);

  // expected-error-re@rtti_manual.h:* {{GetTypeIndex(object){{.*}}ADD_METHODS}}
  // expected-error-re@rtti_manual.h:* {{GetTypeIndex(object){{.*}}SET_TYPE_ID}}
  (void)GetTypeIndex(plain);
}

[[maybe_unused]] void TestDynamicCastErrors(const ValidBase* const_base_ptr,
                                            ValidLeaf* leaf_ptr,
                                            ValidSibling* sibling_ptr) {
  // Dropping const:
  // expected-error@rtti_manual.h:* {{casts away qualifiers}}
  (void)DynamicCast<ValidLeaf*>(const_base_ptr);

  // Upcast (ValidLeaf* -> ValidBase*):
  // expected-error@rtti_manual.h:* {{must inherit from From}}
  (void)DynamicCast<ValidBase*>(leaf_ptr);

  // Cross-cast between siblings (ValidSibling* -> ValidMiddle*):
  // expected-error@rtti_manual.h:* {{must inherit from From}}
  // expected-error@rtti_manual.h:* {{not related by inheritance}}
  (void)DynamicCast<ValidMiddle*>(sibling_ptr);

  // Virtual base downcast rejected at compile time by static_cast:
  // expected-error@rtti_manual.h:* {{via virtual base}}
  (void)DynamicCast<const VirtualDerived*>(const_base_ptr);

  // Non-pointer target type:
  // expected-error@rtti_manual.h:* {{only supports pointer target types}}
  (void)DynamicCast<const ValidLeaf>(const_base_ptr);
}

class UnannotatedSourceBase {
 public:
  virtual ~UnannotatedSourceBase() = default;
};

class AnnotatedChildOfUnannotated : public UnannotatedSourceBase {
 private:
  TINK_RTTI_ADD_METHODS_BASE();
  TEST_RTTI_SET_TYPE_ID(140);
};

[[maybe_unused]] void TestUnannotatedSourceInDynamicCast(
    const UnannotatedSourceBase* source_ptr) {
  // expected-error@rtti_manual.h:* {{Source and target types of DynamicCast}}
  (void)DynamicCast<const AnnotatedChildOfUnannotated*>(source_ptr);
}

[[maybe_unused]] void TestCompilerRttiIsDisabled(const ValidBase* base_ptr) {
  // Confirms that -fno-rtti is genuinely active during this test.
  // expected-error@+1 {{use of typeid requires -frtti}}
  (void)typeid(*base_ptr);
  // expected-error@+1 {{use of dynamic_cast requires -frtti}}
  (void)dynamic_cast<const ValidLeaf*>(base_ptr);
}
}  // namespace test_call_site_errors

// Sanity check that valid usages in this translation unit compile cleanly.
[[maybe_unused]] const ValidLeaf* ValidUsage(const ValidBase* base_ptr) {
  (void)GetTypeIndex<Tag1>();
  (void)GetTypeIndex<ValidTemplate<Tag1>>();
  if (base_ptr != nullptr) {
    (void)GetTypeIndex(*base_ptr);
  }
  return DynamicCast<const ValidLeaf*>(base_ptr);
}

#else  // defined(TINK_USE_CUSTOM_RTTI)

// When compiled with `-fno-rtti` and without `-DTINK_USE_CUSTOM_RTTI`,
// including `rtti.h`, annotating classes with `TINK_RTTI_*` macros, and
// referencing `GetTypeIndex` or `DynamicCast` in uninstantiated templates must
// compile cleanly, while instantiating `GetTypeIndex` or `DynamicCast` must
// fail with a static_assert.

template <typename T>
TypeIndex UninstantiatedGetTypeIndexStatic() {
  return GetTypeIndex<T>();
}

template <typename T>
TypeIndex UninstantiatedGetTypeIndexDynamic(const T& obj) {
  return GetTypeIndex(obj);
}

template <typename To, typename From>
To UninstantiatedDynamicCast(From* from) {
  return DynamicCast<To>(from);
}

[[maybe_unused]] void TestInstantiatingWithoutRttiFails(
    const ValidBase* base_ptr) {
  // expected-error@rtti_native.h:* {{GetTypeIndex requires -frtti}}
  (void)GetTypeIndex<ValidBase>();

  // expected-error@rtti_native.h:* {{GetTypeIndex requires -frtti}}
  (void)GetTypeIndex(*base_ptr);

  // expected-error@rtti_native.h:* {{DynamicCast requires -frtti}}
  (void)DynamicCast<const ValidLeaf*>(base_ptr);
}

#endif  // defined(TINK_USE_CUSTOM_RTTI)

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
