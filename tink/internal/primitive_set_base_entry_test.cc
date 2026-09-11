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

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/string_view.h"
#include "tink/crypto_format.h"
#include "tink/internal/primitive_set_base.h"
#include "tink/mac.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::test::DummyMac;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsNull;
using ::testing::NotNull;
using ::testing::SizeIs;

namespace crypto {
namespace tink {
namespace internal {
namespace {

template <typename T>
PrimitiveSetBase::UntypedPrimitive MakeUntyped(std::unique_ptr<T> obj) {
  return PrimitiveSetBase::UntypedPrimitive(
      obj.release(), [](void* ptr) { delete static_cast<T*>(ptr); });
}

template <typename T>
T* GetTyped(PrimitiveSetBase::EntryBase* entry) {
  if (entry == nullptr) return nullptr;
  return static_cast<T*>(entry->get_untyped_primitive());
}

template <typename T>
const T* GetTyped(const PrimitiveSetBase::EntryBase* entry) {
  if (entry == nullptr) return nullptr;
  return static_cast<const T*>(entry->get_untyped_primitive());
}

KeysetInfo::KeyInfo CreateKey(uint32_t key_id,
                              OutputPrefixType output_prefix_type,
                              KeyStatusType key_status,
                              absl::string_view type_url = "type_url") {
  KeysetInfo::KeyInfo key_info;
  key_info.set_output_prefix_type(output_prefix_type);
  key_info.set_key_id(key_id);
  key_info.set_status(key_status);
  std::string type_url_str(type_url);
  key_info.set_type_url(type_url_str);
  return key_info;
}

struct LifetimeTracker {
  bool* deleted;
  ~LifetimeTracker() {
    if (deleted != nullptr) {
      *deleted = true;
    }
  }
};

struct DummyCustomPrimitive {
  std::string name;
};

// -----------------------------------------------------------------------------
// EntryBase unit tests and lifecycle tests
// -----------------------------------------------------------------------------

TEST(EntryBaseTest, CreationAndAccessorsSuccess) {
  KeysetInfo::KeyInfo key_info = CreateKey(
      12345, OutputPrefixType::TINK, KeyStatusType::ENABLED, "type.url/mac");

  absl::StatusOr<std::unique_ptr<PrimitiveSetBase::EntryBase>> entry_or =
      PrimitiveSetBase::EntryBase::New(
          MakeUntyped(std::make_unique<DummyMac>("MAC1")), key_info);
  ASSERT_THAT(entry_or, IsOk());
  std::unique_ptr<PrimitiveSetBase::EntryBase> entry =
      std::move(entry_or.value());

  EXPECT_THAT(entry->get_key_id(), Eq(12345));
  EXPECT_THAT(entry->get_status(), Eq(KeyStatusType::ENABLED));
  EXPECT_THAT(entry->get_output_prefix_type(), Eq(OutputPrefixType::TINK));
  EXPECT_THAT(entry->get_key_type_url(), Eq("type.url/mac"));
  EXPECT_THAT(entry->get_identifier(),
              Eq(*CryptoFormat::GetOutputPrefix(key_info)));

  Mac* mac = GetTyped<Mac>(entry.get());
  ASSERT_THAT(mac, NotNull());
  EXPECT_THAT(mac->ComputeMac("data"), IsOk());
}

TEST(EntryBaseTest, WithIdRequirementHasEmptyIdentifier) {
  KeysetInfo::KeyInfo key_info =
      CreateKey(12345, OutputPrefixType::WITH_ID_REQUIREMENT,
                KeyStatusType::ENABLED, "type.url/mac");

  absl::StatusOr<std::unique_ptr<PrimitiveSetBase::EntryBase>> entry_or =
      PrimitiveSetBase::EntryBase::New(
          MakeUntyped(std::make_unique<DummyMac>("MAC1")), key_info);
  ASSERT_THAT(entry_or, IsOk());
  EXPECT_THAT(entry_or.value()->get_identifier(), Eq(""));
}

TEST(EntryBaseTest, CreationFailsOnDisabledKey) {
  KeysetInfo::KeyInfo key_info = CreateKey(
      12345, OutputPrefixType::TINK, KeyStatusType::DISABLED, "type.url/mac");

  absl::StatusOr<std::unique_ptr<PrimitiveSetBase::EntryBase>> entry_or =
      PrimitiveSetBase::EntryBase::New(
          MakeUntyped(std::make_unique<DummyMac>("MAC1")), key_info);
  EXPECT_THAT(entry_or, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EntryBaseTest, CreationFailsOnNullPrimitive) {
  KeysetInfo::KeyInfo key_info = CreateKey(
      12345, OutputPrefixType::TINK, KeyStatusType::ENABLED, "type.url/mac");

  absl::StatusOr<std::unique_ptr<PrimitiveSetBase::EntryBase>> entry_or =
      PrimitiveSetBase::EntryBase::New(
          PrimitiveSetBase::UntypedPrimitive(nullptr, [](void*) {}), key_info);
  EXPECT_THAT(entry_or, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EntryBaseTest, CreationFailsOnUnknownPrefixType) {
  KeysetInfo::KeyInfo key_info =
      CreateKey(12345, OutputPrefixType::UNKNOWN_PREFIX, KeyStatusType::ENABLED,
                "type.url/mac");

  absl::StatusOr<std::unique_ptr<PrimitiveSetBase::EntryBase>> entry_or =
      PrimitiveSetBase::EntryBase::New(
          MakeUntyped(std::make_unique<DummyMac>("MAC1")), key_info);
  EXPECT_THAT(entry_or, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EntryBaseTest, ReleaseUntypedPrimitive) {
  KeysetInfo::KeyInfo key_info = CreateKey(
      12345, OutputPrefixType::TINK, KeyStatusType::ENABLED, "type.url/mac");

  absl::StatusOr<std::unique_ptr<PrimitiveSetBase::EntryBase>> entry_or =
      PrimitiveSetBase::EntryBase::New(
          MakeUntyped(std::make_unique<DummyMac>("MAC1")), key_info);
  ASSERT_THAT(entry_or, IsOk());
  std::unique_ptr<PrimitiveSetBase::EntryBase> entry =
      std::move(entry_or.value());

  void* raw_ptr = entry->ReleaseUntypedPrimitive();
  ASSERT_THAT(raw_ptr, NotNull());
  EXPECT_THAT(entry->get_untyped_primitive(), IsNull());

  std::unique_ptr<Mac> mac(static_cast<Mac*>(raw_ptr));
  EXPECT_THAT(mac->ComputeMac("data"), IsOk());
}

TEST(EntryBaseTest, CustomStructLifecycleAndDeleter) {
  bool deleted = false;
  std::unique_ptr<LifetimeTracker> tracker =
      std::make_unique<LifetimeTracker>();
  tracker->deleted = &deleted;

  KeysetInfo::KeyInfo key_info = CreateKey(
      42, OutputPrefixType::TINK, KeyStatusType::ENABLED, "type.url/custom");

  {
    absl::StatusOr<std::unique_ptr<PrimitiveSetBase::EntryBase>> entry_or =
        PrimitiveSetBase::EntryBase::New(MakeUntyped(std::move(tracker)),
                                         key_info);
    ASSERT_THAT(entry_or, IsOk());
    EXPECT_FALSE(deleted);
  }
  // EntryBase destroyed; custom deleter should have run.
  EXPECT_TRUE(deleted);
}

TEST(EntryBaseTest,
     ReleaseUntypedPrimitiveDoesNotRunDeleterOnEntryDestruction) {
  bool deleted = false;
  std::unique_ptr<LifetimeTracker> tracker =
      std::make_unique<LifetimeTracker>();
  tracker->deleted = &deleted;

  KeysetInfo::KeyInfo key_info = CreateKey(
      42, OutputPrefixType::TINK, KeyStatusType::ENABLED, "type.url/custom");

  void* raw_ptr = nullptr;
  {
    absl::StatusOr<std::unique_ptr<PrimitiveSetBase::EntryBase>> entry_or =
        PrimitiveSetBase::EntryBase::New(MakeUntyped(std::move(tracker)),
                                         key_info);
    ASSERT_THAT(entry_or, IsOk());
    std::unique_ptr<PrimitiveSetBase::EntryBase> entry =
        std::move(entry_or.value());
    raw_ptr = entry->ReleaseUntypedPrimitive();
    ASSERT_THAT(raw_ptr, NotNull());
    EXPECT_FALSE(deleted);
  }
  // EntryBase destroyed, but primitive was released; should NOT be deleted yet.
  EXPECT_FALSE(deleted);

  // Manually delete the released pointer.
  delete static_cast<LifetimeTracker*>(raw_ptr);
  EXPECT_TRUE(deleted);
}

// -----------------------------------------------------------------------------
// Additional PrimitiveSetBase::Builder and Lifecycle tests
// -----------------------------------------------------------------------------

TEST(PrimitiveSetBaseEntryTest, BuildWithoutPrimary) {
  KeysetInfo::KeyInfo key =
      CreateKey(101, OutputPrefixType::TINK, KeyStatusType::ENABLED);

  absl::StatusOr<PrimitiveSetBase> pset_or =
      PrimitiveSetBase::Builder{}
          .AddPrimitive(MakeUntyped(std::make_unique<DummyMac>("MAC")), key)
          .Build();
  ASSERT_THAT(pset_or, IsOk());
  EXPECT_THAT(pset_or.value().get_primary(), IsNull());
}

TEST(PrimitiveSetBaseEntryTest, BuilderAddAnnotations) {
  KeysetInfo::KeyInfo key =
      CreateKey(101, OutputPrefixType::TINK, KeyStatusType::ENABLED);

  absl::flat_hash_map<std::string, std::string> annotations_1 = {
      {"key1", "val1"}, {"key2", "val2"}};
  absl::flat_hash_map<std::string, std::string> annotations_2 = {
      {"key2", "ignored_val"}, {"key3", "val3"}};

  absl::StatusOr<PrimitiveSetBase> pset_or =
      PrimitiveSetBase::Builder{}
          .AddAnnotations(annotations_1)
          .AddAnnotations(annotations_2)
          .AddPrimitive(MakeUntyped(std::make_unique<DummyMac>("MAC")), key)
          .Build();

  ASSERT_THAT(pset_or, IsOk());
  const absl::flat_hash_map<std::string, std::string>& annotations =
      pset_or.value().get_annotations();
  EXPECT_THAT(annotations.size(), Eq(3));
  EXPECT_THAT(annotations.at("key1"), Eq("val1"));
  EXPECT_THAT(annotations.at("key2"), Eq("val2"));
  EXPECT_THAT(annotations.at("key3"), Eq("val3"));
}

TEST(PrimitiveSetBaseEntryTest, BuilderFailsOnNullPrimitive) {
  KeysetInfo::KeyInfo key =
      CreateKey(101, OutputPrefixType::TINK, KeyStatusType::ENABLED);

  absl::StatusOr<PrimitiveSetBase> pset_or =
      PrimitiveSetBase::Builder{}
          .AddPrimitive(
              PrimitiveSetBase::UntypedPrimitive(nullptr, [](void*) {}), key)
          .Build();
  EXPECT_THAT(pset_or, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PrimitiveSetBaseEntryTest, BuilderFailsOnAddPrimaryPrimitiveError) {
  KeysetInfo::KeyInfo key =
      CreateKey(101, OutputPrefixType::TINK, KeyStatusType::DISABLED);

  absl::StatusOr<PrimitiveSetBase> pset_or =
      PrimitiveSetBase::Builder{}
          .AddPrimaryPrimitive(MakeUntyped(std::make_unique<DummyMac>("MAC")),
                               key)
          .Build();
  EXPECT_THAT(pset_or, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PrimitiveSetBaseEntryTest, BuilderLvalueAndErrorShortCircuit) {
  PrimitiveSetBase::Builder builder;

  KeysetInfo::KeyInfo valid_key =
      CreateKey(1, OutputPrefixType::TINK, KeyStatusType::ENABLED);
  KeysetInfo::KeyInfo invalid_key =
      CreateKey(2, OutputPrefixType::TINK, KeyStatusType::DISABLED);

  builder.AddAnnotations({{"k1", "v1"}});
  builder.AddPrimitive(MakeUntyped(std::make_unique<DummyMac>("MAC1")),
                       valid_key);
  builder.AddPrimitive(MakeUntyped(std::make_unique<DummyMac>("MAC2")),
                       invalid_key);
  // Subsequent additions after error are short-circuited.
  builder.AddPrimaryPrimitive(MakeUntyped(std::make_unique<DummyMac>("MAC3")),
                              valid_key);

  absl::StatusOr<PrimitiveSetBase> pset_or = std::move(builder).Build();
  EXPECT_THAT(pset_or, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PrimitiveSetBaseEntryTest, MoveSemantics) {
  KeysetInfo::KeyInfo key_1 =
      CreateKey(1, OutputPrefixType::TINK, KeyStatusType::ENABLED);

  absl::StatusOr<PrimitiveSetBase> pset_or =
      PrimitiveSetBase::Builder{}
          .AddPrimaryPrimitive(MakeUntyped(std::make_unique<DummyMac>("MAC1")),
                               key_1)
          .Build();
  ASSERT_THAT(pset_or, IsOk());
  PrimitiveSetBase pset = std::move(pset_or.value());

  // Move construct
  PrimitiveSetBase moved_pset = std::move(pset);
  ASSERT_THAT(moved_pset.get_primary(), NotNull());
  EXPECT_THAT(moved_pset.get_primary()->get_key_id(), Eq(1));

  // Move assign
  PrimitiveSetBase assigned_pset;
  assigned_pset = std::move(moved_pset);
  ASSERT_THAT(assigned_pset.get_primary(), NotNull());
  EXPECT_THAT(assigned_pset.get_primary()->get_key_id(), Eq(1));
}

TEST(PrimitiveSetBaseEntryTest, CustomStructPrimitives) {
  KeysetInfo::KeyInfo key_1 =
      CreateKey(101, OutputPrefixType::TINK, KeyStatusType::ENABLED);
  KeysetInfo::KeyInfo key_2 =
      CreateKey(102, OutputPrefixType::RAW, KeyStatusType::ENABLED);

  absl::StatusOr<PrimitiveSetBase> pset_or =
      PrimitiveSetBase::Builder{}
          .AddPrimaryPrimitive(
              MakeUntyped(std::make_unique<DummyCustomPrimitive>(
                  DummyCustomPrimitive{"primary_custom"})),
              key_1)
          .AddPrimitive(MakeUntyped(std::make_unique<DummyCustomPrimitive>(
                            DummyCustomPrimitive{"raw_custom"})),
                        key_2)
          .Build();

  ASSERT_THAT(pset_or, IsOk());
  PrimitiveSetBase pset = std::move(pset_or.value());

  const PrimitiveSetBase::EntryBase* primary = pset.get_primary();
  ASSERT_THAT(primary, NotNull());
  const DummyCustomPrimitive* primary_obj =
      GetTyped<DummyCustomPrimitive>(primary);
  ASSERT_THAT(primary_obj, NotNull());
  EXPECT_THAT(primary_obj->name, Eq("primary_custom"));

  absl::StatusOr<const PrimitiveSetBase::Primitives*> raw_primitives_or =
      pset.get_raw_primitives();
  ASSERT_THAT(raw_primitives_or, IsOk());
  ASSERT_THAT(*raw_primitives_or.value(), SizeIs(1));
  const DummyCustomPrimitive* raw_obj =
      GetTyped<DummyCustomPrimitive>((*raw_primitives_or.value())[0].get());
  ASSERT_THAT(raw_obj, NotNull());
  EXPECT_THAT(raw_obj->name, Eq("raw_custom"));
}

TEST(PrimitiveSetBaseEntryTest, CrunchyOutputPrefixType) {
  KeysetInfo::KeyInfo key =
      CreateKey(999, OutputPrefixType::CRUNCHY, KeyStatusType::ENABLED);

  absl::StatusOr<PrimitiveSetBase> pset_or =
      PrimitiveSetBase::Builder{}
          .AddPrimaryPrimitive(
              MakeUntyped(std::make_unique<DummyMac>("CRUNCHY_MAC")), key)
          .Build();

  ASSERT_THAT(pset_or, IsOk());
  PrimitiveSetBase pset = std::move(pset_or.value());

  std::string prefix = *CryptoFormat::GetOutputPrefix(key);
  absl::StatusOr<const PrimitiveSetBase::Primitives*> primitives_or =
      pset.get_primitives(prefix);
  ASSERT_THAT(primitives_or, IsOk());
  ASSERT_THAT(*primitives_or.value(), SizeIs(1));
  EXPECT_THAT((*primitives_or.value())[0]->get_output_prefix_type(),
              Eq(OutputPrefixType::CRUNCHY));
}

TEST(PrimitiveSetBaseEntryTest,
     ReleaseAllEntriesMultipleCallsAndDuplicatePrefixes) {
  KeysetInfo::KeyInfo key_1 =
      CreateKey(10, OutputPrefixType::TINK, KeyStatusType::ENABLED, "type_1");
  KeysetInfo::KeyInfo key_2 =
      CreateKey(10, OutputPrefixType::TINK, KeyStatusType::ENABLED, "type_2");
  KeysetInfo::KeyInfo key_3 =
      CreateKey(20, OutputPrefixType::RAW, KeyStatusType::ENABLED, "type_3");

  absl::StatusOr<PrimitiveSetBase> pset_or =
      PrimitiveSetBase::Builder{}
          .AddPrimitive(MakeUntyped(std::make_unique<DummyMac>("MAC1")), key_1)
          .AddPrimitive(MakeUntyped(std::make_unique<DummyMac>("MAC2")), key_2)
          .AddPrimaryPrimitive(MakeUntyped(std::make_unique<DummyMac>("MAC3")),
                               key_3)
          .Build();

  ASSERT_THAT(pset_or, IsOk());
  PrimitiveSetBase pset = std::move(pset_or.value());

  std::vector<std::unique_ptr<PrimitiveSetBase::EntryBase>> released =
      pset.ReleaseAllEntries();
  ASSERT_THAT(released, SizeIs(3));
  EXPECT_THAT(released[0]->get_key_type_url(), Eq("type_1"));
  EXPECT_THAT(released[1]->get_key_type_url(), Eq("type_2"));
  EXPECT_THAT(released[2]->get_key_type_url(), Eq("type_3"));

  // Subsequent call returns empty vector.
  std::vector<std::unique_ptr<PrimitiveSetBase::EntryBase>> released_second =
      pset.ReleaseAllEntries();
  EXPECT_THAT(released_second, SizeIs(0));
}

}  // namespace

class PrimitiveSetBaseInternalTest : public ::testing::Test {
 protected:
  class TestEntryBase : public PrimitiveSetBase::EntryBase {
   public:
    TestEntryBase(PrimitiveSetBase::UntypedPrimitive primitive,
                  const std::string& identifier,
                  google::crypto::tink::KeyStatusType status, uint32_t key_id,
                  google::crypto::tink::OutputPrefixType output_prefix_type,
                  absl::string_view key_type_url)
        : PrimitiveSetBase::EntryBase(std::move(primitive), identifier, status,
                                      key_id, output_prefix_type,
                                      key_type_url) {}
  };

  static absl::Status SetPrimaryImpl(
      PrimitiveSetBase::EntryBase** output,
      PrimitiveSetBase::EntryBase* primary,
      const PrimitiveSetBase::CiphertextPrefixToPrimitivesMap& primitives) {
    return PrimitiveSetBase::SetPrimaryImpl(output, primary, primitives);
  }
};

TEST_F(PrimitiveSetBaseInternalTest, AddPrimaryPrimitiveDisabledFails) {
  PrimitiveSetBase::Builder pset_builder;
  KeysetInfo::KeyInfo disabled_key =
      CreateKey(1, OutputPrefixType::TINK, KeyStatusType::DISABLED);

  pset_builder.AddPrimaryPrimitive(
      MakeUntyped(std::make_unique<DummyMac>("MAC1")), disabled_key);

  EXPECT_THAT(
      std::move(pset_builder).Build(),
      StatusIs(absl::StatusCode::kInvalidArgument, "The key must be ENABLED."));
}

TEST_F(PrimitiveSetBaseInternalTest, SetPrimaryImplNullPrimaryFails) {
  PrimitiveSetBase::EntryBase* output = nullptr;
  PrimitiveSetBase::CiphertextPrefixToPrimitivesMap primitives;

  EXPECT_THAT(SetPrimaryImpl(&output, nullptr, primitives),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "The primary primitive must be non-null."));
}

TEST_F(PrimitiveSetBaseInternalTest, SetPrimaryImplDisabledPrimaryFails) {
  std::unique_ptr<TestEntryBase> entry = std::make_unique<TestEntryBase>(
      MakeUntyped(std::make_unique<DummyMac>("MAC1")), "identifier",
      KeyStatusType::DISABLED, 1, OutputPrefixType::TINK, "type_url");

  PrimitiveSetBase::EntryBase* output = nullptr;
  PrimitiveSetBase::CiphertextPrefixToPrimitivesMap primitives;
  std::string id = entry->get_identifier();
  PrimitiveSetBase::EntryBase* raw_entry = entry.get();
  primitives[id].push_back(std::move(entry));

  EXPECT_THAT(SetPrimaryImpl(&output, raw_entry, primitives),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "Primary has to be enabled."));
}

TEST_F(PrimitiveSetBaseInternalTest, SetPrimaryImplEntryNotHeldFails) {
  KeysetInfo::KeyInfo key =
      CreateKey(1, OutputPrefixType::TINK, KeyStatusType::ENABLED);
  absl::StatusOr<std::unique_ptr<PrimitiveSetBase::EntryBase>> entry =
      PrimitiveSetBase::EntryBase::New(
          MakeUntyped(std::make_unique<DummyMac>("MAC1")), key);
  ASSERT_THAT(entry, IsOk());

  PrimitiveSetBase::EntryBase* output = nullptr;
  PrimitiveSetBase::CiphertextPrefixToPrimitivesMap empty_primitives;

  EXPECT_THAT(
      SetPrimaryImpl(&output, entry->get(), empty_primitives),
      StatusIs(absl::StatusCode::kInvalidArgument,
               "Primary cannot be set to an entry which is not held by this "
               "primitive set."));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
