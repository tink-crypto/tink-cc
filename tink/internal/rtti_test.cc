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

#include "tink/internal/rtti.h"

#include <cstdint>
#if !defined(TINK_USE_CUSTOM_RTTI)
#include <typeindex>
#include <typeinfo>
#endif

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;

// Alias macros so check_rtti_type_ids.sh ignores unit-test fake classes.
#define TEST_RTTI_SET_TYPE_ID TINK_RTTI_SET_TYPE_ID
#define TEST_RTTI_COMPUTE_TYPE_ID TINK_RTTI_COMPUTE_TYPE_ID

constexpr uint64_t kFakeParametersTypeId = 1;
constexpr uint64_t kFakeAeadParametersTypeId = 2;
constexpr uint64_t kFakeAesGcmParametersTypeId = 3;
constexpr uint64_t kFakeKeyTypeId = 5;
constexpr uint64_t kFakePrivateKeyTypeId = 6;
constexpr uint64_t kFakeSignaturePublicKeyTypeId = 7;
constexpr uint64_t kFakeSignaturePrivateKeyTypeId = 8;
constexpr uint64_t kFakeEcdsaPublicKeyTypeId = 9;
constexpr uint64_t kFakeEcdsaPrivateKeyTypeId = 10;
constexpr uint64_t kTagATypeId = 15;
constexpr uint64_t kTagBTypeId = 16;
constexpr uint64_t kTagCTypeId = 17;
constexpr uint64_t kFakeKeyManagerBaseTypeId = 18;
constexpr uint64_t kFakeKeyManagerTypeId = 19;
constexpr uint64_t kFakePrimitiveWrapperTypeId = 20;
constexpr uint64_t kConcreteWrapperABTypeId = 21;
constexpr uint64_t kOtherConcreteWrapperABTypeId = 22;
constexpr uint64_t kFakeTripleTemplateTypeId = 23;

class FakeParameters {
 public:
  virtual ~FakeParameters() = default;

 private:
  TEST_RTTI_SET_TYPE_ID(kFakeParametersTypeId);
};

class FakeAeadParameters : public FakeParameters {
 private:
  TEST_RTTI_SET_TYPE_ID(kFakeAeadParametersTypeId);
};

class FakeAesGcmParameters : public FakeAeadParameters {
 private:
  TEST_RTTI_SET_TYPE_ID(kFakeAesGcmParametersTypeId);
};

class FakeKey {
 public:
  virtual ~FakeKey() = default;

 private:
  TEST_RTTI_SET_TYPE_ID(kFakeKeyTypeId);
};

class FakePrivateKey : public FakeKey {
 private:
  TEST_RTTI_SET_TYPE_ID(kFakePrivateKeyTypeId);
};

class FakeSignaturePublicKey : public FakeKey {
 private:
  TEST_RTTI_SET_TYPE_ID(kFakeSignaturePublicKeyTypeId);
};

class FakeSignaturePrivateKey : public FakePrivateKey {
 private:
  TEST_RTTI_SET_TYPE_ID(kFakeSignaturePrivateKeyTypeId);
};

class FakeEcdsaPublicKey : public FakeSignaturePublicKey {
 private:
  TEST_RTTI_SET_TYPE_ID(kFakeEcdsaPublicKeyTypeId);
};

class FakeEcdsaPrivateKey : public FakeSignaturePrivateKey {
 private:
  TEST_RTTI_SET_TYPE_ID(kFakeEcdsaPrivateKeyTypeId);
};

struct TagA {
  TEST_RTTI_SET_TYPE_ID(kTagATypeId);
};
struct TagB {
  TEST_RTTI_SET_TYPE_ID(kTagBTypeId);
};
struct TagC {
  TEST_RTTI_SET_TYPE_ID(kTagCTypeId);
};

class FakeKeyManagerBase {
 public:
  virtual ~FakeKeyManagerBase() = default;

 private:
  TEST_RTTI_SET_TYPE_ID(kFakeKeyManagerBaseTypeId);
};

template <typename P>
class FakeKeyManager : public FakeKeyManagerBase {
 private:
  TEST_RTTI_COMPUTE_TYPE_ID(kFakeKeyManagerTypeId, P);
};

template <typename InputPrimitive, typename OutputPrimitive>
class FakePrimitiveWrapper {
 public:
  virtual ~FakePrimitiveWrapper() = default;

 private:
  TEST_RTTI_COMPUTE_TYPE_ID(kFakePrimitiveWrapperTypeId, InputPrimitive,
                            OutputPrimitive);
};

class ConcreteWrapperAB : public FakePrimitiveWrapper<TagA, TagB> {
 private:
  TEST_RTTI_SET_TYPE_ID(kConcreteWrapperABTypeId);
};

class OtherConcreteWrapperAB : public FakePrimitiveWrapper<TagA, TagB> {
 private:
  TEST_RTTI_SET_TYPE_ID(kOtherConcreteWrapperABTypeId);
};

template <typename P, typename Q, typename R>
class FakeTripleTemplate {
 public:
  virtual ~FakeTripleTemplate() = default;

 private:
  TEST_RTTI_COMPUTE_TYPE_ID(kFakeTripleTemplateTypeId, P, Q, R);
};

TEST(RttiTest, GetTypeIndexStatic) {
#if defined(TINK_USE_CUSTOM_RTTI)
  EXPECT_THAT(GetTypeIndex<FakeEcdsaPublicKey>(),
              Eq(TypeIndex(kFakeEcdsaPublicKeyTypeId)));
  EXPECT_THAT(GetTypeIndex<FakeEcdsaPrivateKey>(),
              Eq(TypeIndex(kFakeEcdsaPrivateKeyTypeId)));
  EXPECT_THAT(GetTypeIndex<FakeAesGcmParameters>(),
              Eq(TypeIndex(kFakeAesGcmParametersTypeId)));
#else
  EXPECT_THAT(GetTypeIndex<FakeEcdsaPublicKey>(),
              Eq(std::type_index(typeid(FakeEcdsaPublicKey))));
  EXPECT_THAT(GetTypeIndex<FakeEcdsaPrivateKey>(),
              Eq(std::type_index(typeid(FakeEcdsaPrivateKey))));
  EXPECT_THAT(GetTypeIndex<FakeAesGcmParameters>(),
              Eq(std::type_index(typeid(FakeAesGcmParameters))));
#endif
  EXPECT_THAT(GetTypeIndex<FakeEcdsaPublicKey>(),
              Not(Eq(GetTypeIndex<FakeEcdsaPrivateKey>())));
  EXPECT_THAT(GetTypeIndex<FakeAesGcmParameters>(),
              Not(Eq(GetTypeIndex<FakeParameters>())));
  EXPECT_THAT(GetTypeIndex<const FakeKey>(), Eq(GetTypeIndex<FakeKey>()));
  EXPECT_THAT(GetTypeIndex<const FakeKey&>(), Eq(GetTypeIndex<FakeKey>()));
  EXPECT_THAT(GetTypeIndex<FakeAesGcmParameters>().name(), Not(IsEmpty()));
}

TEST(RttiTest, ComputeTypeIdForTemplatedClasses) {
#if defined(TINK_USE_CUSTOM_RTTI)
  EXPECT_THAT(
      GetTypeIndex<FakeKeyManager<TagA>>(),
      Eq(TypeIndex(kFakeKeyManagerTypeId | (kTagATypeId << 16))));
  EXPECT_THAT((GetTypeIndex<FakePrimitiveWrapper<TagA, TagB>>()),
              Eq(TypeIndex(kFakePrimitiveWrapperTypeId | (kTagATypeId << 16) |
                           (kTagBTypeId << 32))));
  EXPECT_THAT((GetTypeIndex<FakeTripleTemplate<TagA, TagB, TagC>>()),
              Eq(TypeIndex(kFakeTripleTemplateTypeId | (kTagATypeId << 16) |
                           (kTagBTypeId << 32) | (kTagCTypeId << 48))));
#endif
  EXPECT_THAT(GetTypeIndex<FakeKeyManager<TagA>>(),
              Not(Eq(GetTypeIndex<FakeKeyManager<TagB>>())));

  EXPECT_THAT(GetTypeIndex<ConcreteWrapperAB>(),
              Not(Eq(GetTypeIndex<OtherConcreteWrapperAB>())));
  EXPECT_THAT((GetTypeIndex<FakePrimitiveWrapper<TagA, TagB>>()),
              Not(Eq(GetTypeIndex<ConcreteWrapperAB>())));
  EXPECT_THAT((GetTypeIndex<FakePrimitiveWrapper<TagA, TagB>>()),
              Not(Eq(GetTypeIndex<FakePrimitiveWrapper<TagB, TagA>>())));

  EXPECT_THAT((GetTypeIndex<FakeTripleTemplate<TagA, TagB, TagC>>()),
              Not(Eq(GetTypeIndex<FakeTripleTemplate<TagA, TagC, TagB>>())));
}

TEST(RttiTest, TypeIndexWorksAsHashMapKey) {
  absl::flat_hash_map<TypeIndex, int> map;
  map[GetTypeIndex<TagA>()] = 1;
  map[GetTypeIndex<TagB>()] = 2;
  map[GetTypeIndex<FakeKey>()] = 3;

  EXPECT_THAT(map[GetTypeIndex<TagA>()], Eq(1));
  EXPECT_THAT(map[GetTypeIndex<TagB>()], Eq(2));
  EXPECT_THAT(map[GetTypeIndex<FakeKey>()], Eq(3));
  EXPECT_THAT(GetTypeIndex<TagA>(), Not(Eq(GetTypeIndex<TagB>())));
}

TEST(RttiTest, TypeIndexOrdering) {
  TypeIndex idx_a = GetTypeIndex<TagA>();
  TypeIndex idx_b = GetTypeIndex<TagB>();

  EXPECT_FALSE(idx_a < idx_a);
  EXPECT_NE(idx_a < idx_b, idx_b < idx_a);
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
