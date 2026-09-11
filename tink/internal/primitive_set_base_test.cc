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

#include "tink/internal/primitive_set_base.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>  // NOLINT(build/c++11)
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/crypto_format.h"
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
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::UnorderedElementsAreArray;

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

class PrimitiveSetBaseTest : public ::testing::Test {};

void add_primitives(PrimitiveSetBase::Builder* primitive_set_builder,
                    int key_id_offset, int primitives_count) {
  for (int i = 0; i < primitives_count; i++) {
    int key_id = key_id_offset + i;
    KeysetInfo::KeyInfo key_info;
    key_info.set_output_prefix_type(OutputPrefixType::TINK);
    key_info.set_key_id(key_id);
    key_info.set_status(KeyStatusType::ENABLED);
    std::unique_ptr<Mac> mac(new DummyMac("dummy MAC"));
    primitive_set_builder->AddPrimitive(MakeUntyped(std::move(mac)), key_info);
  }
}

void access_primitives(PrimitiveSetBase* primitive_set, int key_id_offset,
                       int primitives_count) {
  for (int i = 0; i < primitives_count; i++) {
    int key_id = key_id_offset + i;
    KeysetInfo::KeyInfo key_info;
    key_info.set_output_prefix_type(OutputPrefixType::TINK);
    key_info.set_key_id(key_id);
    key_info.set_status(KeyStatusType::ENABLED);
    std::string prefix = CryptoFormat::GetOutputPrefix(key_info).value();
    absl::StatusOr<const PrimitiveSetBase::Primitives*> get_result =
        primitive_set->get_primitives(prefix);
    EXPECT_THAT(get_result, IsOk());
    EXPECT_GE(get_result.value()->size(), 1);
  }
}

TEST_F(PrimitiveSetBaseTest, ConcurrentOperations) {
  PrimitiveSetBase::Builder mac_set_builder;
  int offset_a = 100;
  int offset_b = 150;
  int count = 100;

  // Add some primitives.
  // See go/totw/133 on why we use a lambda here.
  std::thread add_primitives_a(
      [&]() { add_primitives(&mac_set_builder, offset_a, count); });
  std::thread add_primitives_b(
      [&]() { add_primitives(&mac_set_builder, offset_b, count); });
  add_primitives_a.join();
  add_primitives_b.join();

  absl::StatusOr<PrimitiveSetBase> mac_set_result =
      std::move(mac_set_builder).Build();
  ASSERT_THAT(mac_set_result, IsOk());
  PrimitiveSetBase mac_set = std::move(mac_set_result.value());

  // Access primitives.
  std::thread access_primitives_a(access_primitives, &mac_set, offset_a, count);
  std::thread access_primitives_b(access_primitives, &mac_set, offset_b, count);
  access_primitives_a.join();
  access_primitives_b.join();

  // Verify the common key ids added by both threads.
  for (int key_id = offset_a; key_id < offset_b + count; key_id++) {
    KeysetInfo::KeyInfo key_info;
    key_info.set_output_prefix_type(OutputPrefixType::TINK);
    key_info.set_key_id(key_id);
    key_info.set_status(KeyStatusType::ENABLED);
    std::string prefix = CryptoFormat::GetOutputPrefix(key_info).value();
    absl::StatusOr<const PrimitiveSetBase::Primitives*> get_result =
        mac_set.get_primitives(prefix);
    EXPECT_THAT(get_result, IsOk());
    const PrimitiveSetBase::Primitives* macs = get_result.value();
    if (key_id >= offset_b && key_id < offset_a + count) {
      EXPECT_EQ(2, macs->size());  // overlapping key_id range
    } else {
      EXPECT_EQ(1, macs->size());
    }
  }
}

TEST_F(PrimitiveSetBaseTest, Basic) {
  std::string mac_name_1 = "MAC#1";
  std::unique_ptr<Mac> mac_1(new DummyMac(mac_name_1));
  std::string mac_name_2 = "MAC#2";
  std::unique_ptr<Mac> mac_2(new DummyMac(mac_name_2));
  std::string mac_name_3 = "MAC#3";
  std::unique_ptr<Mac> mac_3(new DummyMac(mac_name_3));
  std::string mac_name_4 = "MAC#3";
  std::unique_ptr<Mac> mac_4(new DummyMac(mac_name_4));
  std::string mac_name_5 = "MAC#3";
  std::unique_ptr<Mac> mac_5(new DummyMac(mac_name_5));
  std::string mac_name_6 = "MAC#3";
  std::unique_ptr<Mac> mac_6(new DummyMac(mac_name_6));

  uint32_t key_id_1 = 1234543;
  KeysetInfo::KeyInfo key_1;
  key_1.set_output_prefix_type(OutputPrefixType::TINK);
  key_1.set_key_id(key_id_1);
  key_1.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_2 = 7213743;
  KeysetInfo::KeyInfo key_2;
  key_2.set_output_prefix_type(OutputPrefixType::LEGACY);
  key_2.set_key_id(key_id_2);
  key_2.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_3 = key_id_2;  // same id as key_2
  KeysetInfo::KeyInfo key_3;
  key_3.set_output_prefix_type(OutputPrefixType::TINK);
  key_3.set_key_id(key_id_3);
  key_3.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_4 = 947327;
  KeysetInfo::KeyInfo key_4;
  key_4.set_output_prefix_type(OutputPrefixType::RAW);
  key_4.set_key_id(key_id_4);
  key_4.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_5 = 529472;
  KeysetInfo::KeyInfo key_5;
  key_5.set_output_prefix_type(OutputPrefixType::RAW);
  key_5.set_key_id(key_id_5);
  key_5.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_6 = key_id_1;  // same id as key_1
  KeysetInfo::KeyInfo key_6;
  key_6.set_output_prefix_type(OutputPrefixType::TINK);
  key_6.set_key_id(key_id_6);
  key_6.set_status(KeyStatusType::ENABLED);

  PrimitiveSetBase::Builder primitive_set_builder;

  // Add all the primitives.
  absl::StatusOr<PrimitiveSetBase> primitive_set_result =
      PrimitiveSetBase::Builder{}
          .AddPrimitive(MakeUntyped(std::move(mac_1)), key_1)
          .AddPrimitive(MakeUntyped(std::move(mac_2)), key_2)
          .AddPrimaryPrimitive(MakeUntyped(std::move(mac_3)), key_3)
          .AddPrimitive(MakeUntyped(std::move(mac_4)), key_4)
          .AddPrimitive(MakeUntyped(std::move(mac_5)), key_5)
          .AddPrimitive(MakeUntyped(std::move(mac_6)), key_6)
          .Build();

  ASSERT_THAT(primitive_set_result, IsOk());
  PrimitiveSetBase primitive_set = std::move(primitive_set_result.value());

  std::string data = "some data";

  {  // Check the primary.
    const PrimitiveSetBase::EntryBase* primary = primitive_set.get_primary();
    EXPECT_FALSE(primary == nullptr);
    EXPECT_EQ(KeyStatusType::ENABLED, primary->get_status());
    EXPECT_EQ(DummyMac(mac_name_3).ComputeMac(data).value(),
              GetTyped<Mac>(primary)->ComputeMac(data).value());
  }

  {  // Check raw primitives.
    const PrimitiveSetBase::Primitives& primitives =
        *(primitive_set.get_raw_primitives().value());
    EXPECT_EQ(2, primitives.size());
    EXPECT_EQ(DummyMac(mac_name_4).ComputeMac(data).value(),
              GetTyped<Mac>(primitives[0].get())->ComputeMac(data).value());
    EXPECT_EQ(KeyStatusType::ENABLED, primitives[0]->get_status());
    EXPECT_EQ(key_4.key_id(), primitives[0]->get_key_id());
    EXPECT_EQ(OutputPrefixType::RAW, primitives[0]->get_output_prefix_type());
    EXPECT_EQ(DummyMac(mac_name_5).ComputeMac(data).value(),
              GetTyped<Mac>(primitives[1].get())->ComputeMac(data).value());
    EXPECT_EQ(KeyStatusType::ENABLED, primitives[1]->get_status());
    EXPECT_EQ(key_5.key_id(), primitives[1]->get_key_id());
    EXPECT_EQ(OutputPrefixType::RAW, primitives[1]->get_output_prefix_type());
  }

  {  // Check Tink primitives.
    std::string prefix = CryptoFormat::GetOutputPrefix(key_1).value();
    const PrimitiveSetBase::Primitives& primitives =
        *(primitive_set.get_primitives(prefix).value());
    EXPECT_EQ(2, primitives.size());
    EXPECT_EQ(DummyMac(mac_name_1).ComputeMac(data).value(),
              GetTyped<Mac>(primitives[0].get())->ComputeMac(data).value());
    EXPECT_EQ(KeyStatusType::ENABLED, primitives[0]->get_status());
    EXPECT_EQ(key_1.key_id(), primitives[0]->get_key_id());
    EXPECT_EQ(OutputPrefixType::TINK, primitives[0]->get_output_prefix_type());
    EXPECT_EQ(DummyMac(mac_name_6).ComputeMac(data).value(),
              GetTyped<Mac>(primitives[1].get())->ComputeMac(data).value());
    EXPECT_EQ(KeyStatusType::ENABLED, primitives[1]->get_status());
    EXPECT_EQ(key_1.key_id(), primitives[1]->get_key_id());
    EXPECT_EQ(OutputPrefixType::TINK, primitives[1]->get_output_prefix_type());
  }

  {  // Check another Tink primitive.
    std::string prefix = CryptoFormat::GetOutputPrefix(key_3).value();
    const PrimitiveSetBase::Primitives& primitives =
        *(primitive_set.get_primitives(prefix).value());
    EXPECT_EQ(1, primitives.size());
    EXPECT_EQ(DummyMac(mac_name_3).ComputeMac(data).value(),
              GetTyped<Mac>(primitives[0].get())->ComputeMac(data).value());
    EXPECT_EQ(KeyStatusType::ENABLED, primitives[0]->get_status());
    EXPECT_EQ(key_3.key_id(), primitives[0]->get_key_id());
    EXPECT_EQ(OutputPrefixType::TINK, primitives[0]->get_output_prefix_type());
  }

  {  // Check legacy primitive.
    std::string prefix = CryptoFormat::GetOutputPrefix(key_2).value();
    const PrimitiveSetBase::Primitives& primitives =
        *(primitive_set.get_primitives(prefix).value());
    EXPECT_EQ(1, primitives.size());
    EXPECT_EQ(DummyMac(mac_name_2).ComputeMac(data).value(),
              GetTyped<Mac>(primitives[0].get())->ComputeMac(data).value());
    EXPECT_EQ(KeyStatusType::ENABLED, primitives[0]->get_status());
    EXPECT_EQ(key_2.key_id(), primitives[0]->get_key_id());
    EXPECT_EQ(OutputPrefixType::LEGACY,
              primitives[0]->get_output_prefix_type());
  }
}

TEST_F(PrimitiveSetBaseTest, PrimaryKeyWithIdCollisions) {
  std::string mac_name_1 = "MAC#1";
  std::string mac_name_2 = "MAC#2";

  uint32_t key_id_1 = 1234543;
  KeysetInfo::KeyInfo key_info_1;
  key_info_1.set_key_id(key_id_1);
  key_info_1.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_2 = key_id_1;  // same id as key_2
  KeysetInfo::KeyInfo key_info_2;
  key_info_2.set_key_id(key_id_2);
  key_info_2.set_status(KeyStatusType::ENABLED);

  {  // Test with RAW-keys.
    std::unique_ptr<Mac> mac_1(new DummyMac(mac_name_1));
    std::unique_ptr<Mac> mac_2(new DummyMac(mac_name_2));
    key_info_1.set_output_prefix_type(OutputPrefixType::RAW);
    key_info_2.set_output_prefix_type(OutputPrefixType::RAW);
    PrimitiveSetBase::Builder primitive_set_builder;

    // Add the first primitive, and set it as primary.
    primitive_set_builder.AddPrimaryPrimitive(MakeUntyped(std::move(mac_1)),
                                              key_info_1);

    absl::StatusOr<PrimitiveSetBase> primitive_set_result =
        std::move(primitive_set_builder).Build();
    ASSERT_THAT(primitive_set_result, IsOk());
    PrimitiveSetBase primitive_set = std::move(primitive_set_result.value());

    std::string identifier = "";
    const PrimitiveSetBase::Primitives& primitives =
        *(primitive_set.get_primitives(identifier).value());
    EXPECT_EQ(1, primitives.size());
    EXPECT_EQ(primitive_set.get_primary(), primitives[0].get());
  }

  {  // Test with TINK-keys.
    std::unique_ptr<Mac> mac_1(new DummyMac(mac_name_1));
    std::unique_ptr<Mac> mac_2(new DummyMac(mac_name_2));
    key_info_1.set_output_prefix_type(OutputPrefixType::TINK);
    key_info_2.set_output_prefix_type(OutputPrefixType::TINK);
    PrimitiveSetBase::Builder primitive_set_builder;

    // Add the first primitive, and set it as primary.
    primitive_set_builder.AddPrimaryPrimitive(MakeUntyped(std::move(mac_1)),
                                              key_info_1);

    absl::StatusOr<PrimitiveSetBase> primitive_set_result =
        std::move(primitive_set_builder).Build();
    ASSERT_THAT(primitive_set_result, IsOk());
    PrimitiveSetBase primitive_set = std::move(primitive_set_result.value());
    std::string identifier = CryptoFormat::GetOutputPrefix(key_info_1).value();
    const PrimitiveSetBase::Primitives& primitives =
        *(primitive_set.get_primitives(identifier).value());
    EXPECT_EQ(1, primitives.size());
    EXPECT_EQ(primitive_set.get_primary(), primitives[0].get());
  }

  {  // Test with LEGACY-keys.
    std::unique_ptr<Mac> mac_1(new DummyMac(mac_name_1));
    std::unique_ptr<Mac> mac_2(new DummyMac(mac_name_2));
    key_info_1.set_output_prefix_type(OutputPrefixType::LEGACY);
    key_info_2.set_output_prefix_type(OutputPrefixType::LEGACY);
    PrimitiveSetBase::Builder primitive_set_builder;

    // Add the first primitive, and set it as primary.
    primitive_set_builder.AddPrimaryPrimitive(MakeUntyped(std::move(mac_1)),
                                              key_info_1);

    absl::StatusOr<PrimitiveSetBase> primitive_set_result =
        std::move(primitive_set_builder).Build();
    ASSERT_THAT(primitive_set_result, IsOk());
    PrimitiveSetBase primitive_set = std::move(primitive_set_result.value());
    std::string identifier = CryptoFormat::GetOutputPrefix(key_info_1).value();
    const PrimitiveSetBase::Primitives& primitives =
        *(primitive_set.get_primitives(identifier).value());
    EXPECT_EQ(1, primitives.size());
    EXPECT_EQ(primitive_set.get_primary(), primitives[0].get());
  }
}

TEST_F(PrimitiveSetBaseTest, DisabledKey) {
  std::string mac_name_1 = "MAC#1";
  std::unique_ptr<Mac> mac_1(new DummyMac(mac_name_1));

  uint32_t key_id_1 = 1234543;
  KeysetInfo::KeyInfo key_info_1;
  key_info_1.set_output_prefix_type(OutputPrefixType::TINK);
  key_info_1.set_key_id(key_id_1);
  key_info_1.set_status(KeyStatusType::DISABLED);

  // Add all the primitives.
  absl::StatusOr<PrimitiveSetBase> add_primitive_result =
      PrimitiveSetBase::Builder{}
          .AddPrimitive(MakeUntyped(std::move(mac_1)), key_info_1)
          .Build();
  EXPECT_THAT(add_primitive_result, Not(IsOk()));
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

// Struct to hold MAC, Id and type_url.
struct MacIdAndTypeUrl {
  std::string mac;
  std::string id;
  std::string type_url;

  bool operator==(const MacIdAndTypeUrl& other) const {
    return mac == other.mac && id == other.id && type_url == other.type_url;
  }
};

TEST_F(PrimitiveSetBaseTest, GetAll) {
  absl::StatusOr<PrimitiveSetBase> pset_result =
      PrimitiveSetBase::Builder{}
          .AddPrimitive(
              MakeUntyped(std::make_unique<DummyMac>("MAC1")),
              CreateKey(0x01010101, OutputPrefixType::TINK,
                        KeyStatusType::ENABLED, /*type_url=*/
                        "type.googleapis.com/google.crypto.tink.HmacKey"))
          // WITH_ID_REQUIREMENT has an empty identifier.
          .AddPrimitive(
              MakeUntyped(std::make_unique<DummyMac>("MAC2")),
              CreateKey(0x02020202, OutputPrefixType::WITH_ID_REQUIREMENT,
                        KeyStatusType::ENABLED, /*type_url=*/
                        "type.googleapis.com/google.crypto.tink.HmacKey"))
          // Add primitive and make it primary.
          .AddPrimaryPrimitive(
              MakeUntyped(std::make_unique<DummyMac>("MAC3")),
              CreateKey(0x02020202, OutputPrefixType::TINK,
                        KeyStatusType::ENABLED, /*type_url=*/
                        "type.googleapis.com/google.crypto.tink.AesCmacKey"))
          .AddPrimitive(
              MakeUntyped(std::make_unique<DummyMac>("MAC4")),
              CreateKey(0x02020202, OutputPrefixType::RAW,
                        KeyStatusType::ENABLED, /*type_url=*/
                        "type.googleapis.com/google.crypto.tink.AesCmacKey"))
          .AddPrimitive(
              MakeUntyped(std::make_unique<DummyMac>("MAC5")),
              CreateKey(0x01010101, OutputPrefixType::TINK,
                        KeyStatusType::ENABLED, /*type_url=*/
                        "type.googleapis.com/google.crypto.tink.AesCmacKey"))
          .Build();

  ASSERT_THAT(pset_result, IsOk());
  PrimitiveSetBase pset = std::move(pset_result.value());

  std::vector<MacIdAndTypeUrl> mac_id_and_type;
  for (PrimitiveSetBase::EntryBase* entry : pset.get_all()) {
    absl::StatusOr<std::string> mac_or = GetTyped<Mac>(entry)->ComputeMac("");
    ASSERT_THAT(mac_or, IsOk());
    mac_id_and_type.push_back({mac_or.value(), entry->get_identifier(),
                               std::string(entry->get_key_type_url())});
  }

  // In the following id part, the first byte is 1 for Tink.
  std::vector<MacIdAndTypeUrl> expected_result = {
      {/*mac=*/"13:0:DummyMac:MAC1", /*id=*/absl::StrCat("\1\1\1\1\1"),
       /*type_url=*/"type.googleapis.com/google.crypto.tink.HmacKey"},
      {/*mac=*/"13:0:DummyMac:MAC2", /*id=*/"",
       /*type_url=*/"type.googleapis.com/google.crypto.tink.HmacKey"},
      {/*mac=*/"13:0:DummyMac:MAC3", /*id=*/absl::StrCat("\1\2\2\2\2"),
       /*type_url=*/"type.googleapis.com/google.crypto.tink.AesCmacKey"},
      {/*mac=*/"13:0:DummyMac:MAC4", /*id=*/"",
       /*type_url=*/"type.googleapis.com/google.crypto.tink.AesCmacKey"},
      {/*mac=*/"13:0:DummyMac:MAC5", /*id=*/absl::StrCat("\1\1\1\1\1"),
       /*type_url=*/"type.googleapis.com/google.crypto.tink.AesCmacKey"}};

  EXPECT_THAT(mac_id_and_type, UnorderedElementsAreArray(expected_result));
}

TEST_F(PrimitiveSetBaseTest, GetAllInKeysetOrder) {
  PrimitiveSetBase::Builder pset_builder;
  std::vector<KeysetInfo::KeyInfo> key_infos;

  KeysetInfo::KeyInfo key_info;
  key_info.set_key_id(1010101);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::RAW);
  key_info.set_type_url(
      "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
  pset_builder.AddPrimitive(MakeUntyped(std::make_unique<DummyMac>("one")),
                            key_info);
  key_infos.push_back(key_info);

  key_info.set_key_id(2020202);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::LEGACY);
  key_info.set_type_url(
      "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
  pset_builder.AddPrimitive(MakeUntyped(std::make_unique<DummyMac>("two")),
                            key_info);
  key_infos.push_back(key_info);

  key_info.set_key_id(3030303);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::TINK);
  key_info.set_type_url(
      "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
  pset_builder.AddPrimitive(MakeUntyped(std::make_unique<DummyMac>("three")),
                            key_info);
  key_infos.push_back(key_info);

  absl::StatusOr<PrimitiveSetBase> pset = std::move(pset_builder).Build();
  ASSERT_THAT(pset, IsOk());

  std::vector<PrimitiveSetBase::EntryBase*> entries =
      pset->get_all_in_keyset_order();
  ASSERT_THAT(entries, SizeIs(key_infos.size()));

  for (size_t i = 0; i < entries.size(); i++) {
    EXPECT_THAT(entries[i]->get_identifier(),
                Eq(*CryptoFormat::GetOutputPrefix(key_infos[i])));
    EXPECT_THAT(entries[i]->get_status(), Eq(KeyStatusType::ENABLED));
    EXPECT_THAT(entries[i]->get_key_id(), Eq(key_infos[i].key_id()));
    EXPECT_THAT(entries[i]->get_output_prefix_type(),
                Eq(key_infos[i].output_prefix_type()));
    EXPECT_THAT(entries[i]->get_key_type_url(), Eq(key_infos[i].type_url()));
  }
}

TEST_F(PrimitiveSetBaseTest, ReleaseAllEntries) {
  PrimitiveSetBase::Builder pset_builder;

  KeysetInfo::KeyInfo key_info_1 = CreateKey(
      1, OutputPrefixType::TINK, KeyStatusType::ENABLED, "type_url_1");
  pset_builder.AddPrimitive(MakeUntyped(std::make_unique<DummyMac>("MAC1")),
                            key_info_1);

  KeysetInfo::KeyInfo key_info_2 =
      CreateKey(2, OutputPrefixType::RAW, KeyStatusType::ENABLED, "type_url_2");
  pset_builder.AddPrimaryPrimitive(
      MakeUntyped(std::make_unique<DummyMac>("MAC2")), key_info_2);

  absl::StatusOr<PrimitiveSetBase> pset = std::move(pset_builder).Build();
  ASSERT_THAT(pset, IsOk());

  std::vector<std::unique_ptr<PrimitiveSetBase::EntryBase>> released =
      pset->ReleaseAllEntries();

  ASSERT_THAT(released, SizeIs(2));

  // Verify first entry (TINK)
  EXPECT_EQ(released[0]->get_key_id(), 1);
  EXPECT_EQ(released[0]->get_output_prefix_type(), OutputPrefixType::TINK);
  EXPECT_EQ(released[0]->get_key_type_url(), "type_url_1");
  void* mac1_raw = released[0]->ReleaseUntypedPrimitive();
  ASSERT_NE(mac1_raw, nullptr);
  std::unique_ptr<Mac> mac1(static_cast<Mac*>(mac1_raw));
  absl::StatusOr<std::string> mac1_val = mac1->ComputeMac("");
  ASSERT_THAT(mac1_val, IsOk());
  EXPECT_EQ(mac1_val.value(), "13:0:DummyMac:MAC1");

  // Verify second entry (RAW, primary)
  EXPECT_EQ(released[1]->get_key_id(), 2);
  EXPECT_EQ(released[1]->get_output_prefix_type(), OutputPrefixType::RAW);
  EXPECT_EQ(released[1]->get_key_type_url(), "type_url_2");
  void* mac2_raw = released[1]->ReleaseUntypedPrimitive();
  ASSERT_NE(mac2_raw, nullptr);
  std::unique_ptr<Mac> mac2(static_cast<Mac*>(mac2_raw));
  absl::StatusOr<std::string> mac2_val = mac2->ComputeMac("");
  ASSERT_THAT(mac2_val, IsOk());
  EXPECT_EQ(mac2_val.value(), "13:0:DummyMac:MAC2");

  // Verify PrimitiveSet is now empty
  EXPECT_EQ(pset->get_primary(), nullptr);
  EXPECT_THAT(pset->get_all(), SizeIs(0));
  EXPECT_THAT(pset->get_all_in_keyset_order(), SizeIs(0));
  EXPECT_THAT(pset->get_raw_primitives(),
              StatusIs(absl::StatusCode::kNotFound));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
