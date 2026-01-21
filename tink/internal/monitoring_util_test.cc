// Copyright 2022 Google LLC
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
#include "tink/internal/monitoring_util.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/monitoring_key_set_info.h"
#include "tink/key_status.h"
#include "tink/primitive_set.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::MonitoringKeySetInfo;
using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::UnorderedElementsAre;
using ::testing::UnorderedElementsAreArray;

TEST(MonitoringUtilTest,
     MonitoringKeySetInfoFromPrimitiveSetEmptyPrimitiveSet) {
  PrimitiveSet<std::string> primitive_set;
  EXPECT_THAT(MonitoringKeySetInfoFromPrimitiveSet(primitive_set).status(),
              test::StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MonitoringUtilTest, MonitoringKeySetInfoFromPrimitiveSetNullPrimary) {
  PrimitiveSet<std::string>::Builder primitive_set_builder;
  auto some_string = absl::make_unique<std::string>("Text");
  KeysetInfo::KeyInfo key_info;
  key_info.set_type_url(
      "type.googleapis.com/google.crypto.tink.SomePrimitiveInstance");
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_key_id(1);
  key_info.set_output_prefix_type(OutputPrefixType::TINK);
  primitive_set_builder.AddPrimitive(std::move(some_string), key_info);
  absl::StatusOr<PrimitiveSet<std::string>> primitive_set =
      std::move(primitive_set_builder).Build();
  ASSERT_THAT(primitive_set, IsOk());
  EXPECT_THAT(MonitoringKeySetInfoFromPrimitiveSet(*primitive_set).status(),
              test::StatusIs(absl::StatusCode::kInvalidArgument));
}

// Utility struct to hold primitive and key info.
template <class P>
struct PrimitiveSetInputPrimitive {
  std::unique_ptr<P> primitive;
  KeysetInfo::KeyInfo key_info;
};

PrimitiveSetInputPrimitive<std::string> NewPrimitiveSetInputPrimitive(
    absl::string_view primitive_value, absl::string_view type_url,
    KeyStatusType status, uint32_t key_id, OutputPrefixType prefix_type) {
  auto some_string = absl::make_unique<std::string>(primitive_value);
  KeysetInfo::KeyInfo key_info;
  std::string type_url_str(type_url);
  key_info.set_type_url(type_url_str);
  key_info.set_status(status);
  key_info.set_key_id(key_id);
  key_info.set_output_prefix_type(prefix_type);
  return {/*primitive=*/std::move(some_string),
          /*key_info=*/std::move(key_info)};
}

MATCHER_P(MonitoringKeySetInfoEntryEq, other, "") {
  return arg.GetStatus() == other.GetStatus() &&
         arg.GetKeyId() == other.GetKeyId() &&
         arg.GetKeyPrefix() == other.GetKeyPrefix() &&
         arg.GetKeyType() == other.GetKeyType();
}

TEST(MonitoringUtilTest, MonitoringKeySetInfoFromPrimitiveSetValid) {
  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"},
      {"key2", "value2"},
  };
  PrimitiveSet<std::string>::Builder primitive_set_builder;
  primitive_set_builder.AddAnnotations(kAnnotations);

  constexpr absl::string_view kPrimitive1KeyTyepUrl =
      "type.googleapis.com/google.crypto.tink.SomePrimitiveInstance";
  constexpr absl::string_view kPrimitive2KeyTypeUrl =
      "type.googleapis.com/google.crypto.tink.SomeOtherPrimitiveInstance";

  PrimitiveSetInputPrimitive<std::string> primitive_1 =
      NewPrimitiveSetInputPrimitive(
          /*primitive_value=*/"primitive_1", kPrimitive1KeyTyepUrl,
          /*status=*/KeyStatusType::ENABLED, /*key_id=*/1,
          /*prefix_type=*/OutputPrefixType::TINK);

  PrimitiveSetInputPrimitive<std::string> primitive_2 =
      NewPrimitiveSetInputPrimitive(
          /*primitive_value=*/"primitive_2", kPrimitive2KeyTypeUrl,
          /*status=*/KeyStatusType::ENABLED, /*key_id=*/2,
          /*prefix_type=*/OutputPrefixType::TINK);

  primitive_set_builder.AddPrimaryPrimitive(std::move(primitive_1.primitive),
                                            primitive_1.key_info);
  primitive_set_builder.AddPrimitive(std::move(primitive_2.primitive),
                                     primitive_2.key_info);

  absl::StatusOr<PrimitiveSet<std::string>> primitive_set =
      std::move(primitive_set_builder).Build();
  ASSERT_THAT(primitive_set, IsOk());

  absl::StatusOr<internal::MonitoringKeySetInfo> monitoring_keyset_info =
      MonitoringKeySetInfoFromPrimitiveSet(*primitive_set);
  ASSERT_THAT(monitoring_keyset_info, IsOk());
  EXPECT_EQ(monitoring_keyset_info->GetPrimaryKeyId(), 1);
  EXPECT_THAT(monitoring_keyset_info->GetAnnotations(),
              UnorderedElementsAreArray(kAnnotations));
  const std::vector<MonitoringKeySetInfo::Entry> &monitoring_entries =
      monitoring_keyset_info->GetEntries();
  EXPECT_THAT(
      monitoring_entries,
      UnorderedElementsAre(
          MonitoringKeySetInfoEntryEq(MonitoringKeySetInfo::Entry(
              KeyStatus::kEnabled,
              /*key_id=*/1, "tink.SomePrimitiveInstance", "TINK")),
          MonitoringKeySetInfoEntryEq(MonitoringKeySetInfo::Entry(
              KeyStatus::kEnabled,
              /*key_id=*/2, "tink.SomeOtherPrimitiveInstance", "TINK"))));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
