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

// Non-compilation tests for Tink RTTI macros and utilities in
// `-DTINK_USE_CUSTOM_RTTI -fno-rtti` mode.

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
  TEST_RTTI_SET_TYPE_ID(10);
};

template <typename T>
class ValidTemplate {
 public:
  virtual ~ValidTemplate() = default;

 private:
  TEST_RTTI_COMPUTE_TYPE_ID(15, T);
};

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
// 3. Subclass and GetTypeIndex<T>() call-site contract checks
// -----------------------------------------------------------------------------

namespace test_subclass_does_not_silently_inherit_annotations {
// Inherits from annotated ValidBase, but forgets TINK_RTTI_SET_TYPE_ID!
class UnannotatedSubclass : public ValidBase {};

[[maybe_unused]] void TestForgottenSubclassMacro() {
  // expected-error@rtti_manual.h:* {{GetTypeIndex<T>() requires T to declare}}
  (void)GetTypeIndex<UnannotatedSubclass>();
}
}  // namespace test_subclass_does_not_silently_inherit_annotations

namespace test_call_site_errors {
struct UnannotatedStruct {};

[[maybe_unused]] void TestGetTypeIndexErrors() {
  // expected-error@rtti_manual.h:* {{GetTypeIndex<T>() requires T to declare}}
  (void)GetTypeIndex<UnannotatedStruct>();
}

class ValidDerived : public ValidBase {
 private:
  TEST_RTTI_SET_TYPE_ID(11);
};

[[maybe_unused]] void TestCompilerRttiIsDisabled(const ValidBase* base_ptr) {
  // Confirms that -fno-rtti is genuinely active during this test.
  // expected-error@+1 {{use of typeid requires -frtti}}
  (void)typeid(*base_ptr);
  // expected-error@+1 {{use of dynamic_cast requires -frtti}}
  (void)dynamic_cast<const ValidDerived*>(base_ptr);
}
}  // namespace test_call_site_errors

// Sanity check that valid usages in this translation unit compile cleanly.
[[maybe_unused]] void ValidUsage() {
  (void)GetTypeIndex<Tag1>();
  (void)GetTypeIndex<ValidTemplate<Tag1>>();
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
