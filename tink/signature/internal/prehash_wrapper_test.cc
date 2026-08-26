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

#include "tink/signature/internal/prehash_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/algorithm/container.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/primitive_set.h"
#include "tink/signature/prehash.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::test::HexDecodeOrDie;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;

TEST(PrehashWrapperTest, WrapNullPtr) {
  EXPECT_THAT(PrehashWrapper().Wrap(nullptr).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PrehashWrapperTest, WrapEmpty) {
  auto prehash_set = std::make_unique<PrimitiveSet<Prehash>>();
  EXPECT_THAT(PrehashWrapper().Wrap(std::move(prehash_set)).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

class ReverseHash : public Prehash {
 public:
  absl::StatusOr<std::string> Compute(absl::string_view data) const override {
    std::string output = std::string(data);
    absl::c_reverse(output);
    return output;
  }
};

TEST(PrehashWrapperTest, WrapWithRawPrimitive) {
  KeysetInfo::KeyInfo* key_info;
  KeysetInfo keyset_info;

  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::RAW);
  key_info->set_key_id(0x7b);
  key_info->set_status(KeyStatusType::ENABLED);

  PrimitiveSet<Prehash>::Builder prehash_set_builder;
  prehash_set_builder.AddPrimaryPrimitive(std::make_unique<ReverseHash>(),
                                          keyset_info.key_info(0));
  absl::StatusOr<PrimitiveSet<Prehash>> prehash_set =
      std::move(prehash_set_builder).Build();
  ASSERT_THAT(prehash_set, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehash_set_primitive =
      PrehashWrapper().Wrap(
          std::make_unique<PrimitiveSet<Prehash>>(*std::move(prehash_set)));
  EXPECT_THAT(prehash_set_primitive.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PrehashWrapperTest, WrapWithTinkPrimary) {
  KeysetInfo::KeyInfo* key_info;
  KeysetInfo keyset_info;

  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::WITH_ID_REQUIREMENT);
  key_info->set_key_id(0x7b);
  key_info->set_status(KeyStatusType::ENABLED);

  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::LEGACY);
  key_info->set_key_id(0x1c8);
  key_info->set_status(KeyStatusType::ENABLED);

  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_key_id(0x315);
  key_info->set_status(KeyStatusType::ENABLED);

  PrimitiveSet<Prehash>::Builder prehash_set_builder;
  prehash_set_builder.AddPrimitive(std::make_unique<ReverseHash>(),
                                   keyset_info.key_info(0));
  prehash_set_builder.AddPrimitive(std::make_unique<ReverseHash>(),
                                   keyset_info.key_info(1));
  // Primary prehash primitive has key id 0x315 (from above).
  prehash_set_builder.AddPrimaryPrimitive(std::make_unique<ReverseHash>(),
                                          keyset_info.key_info(2));
  absl::StatusOr<PrimitiveSet<Prehash>> prehash_set =
      std::move(prehash_set_builder).Build();
  ASSERT_THAT(prehash_set, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehash_set_primitive =
      PrehashWrapper().Wrap(
          std::make_unique<PrimitiveSet<Prehash>>(*std::move(prehash_set)));
  ASSERT_THAT(prehash_set_primitive, IsOk());

  // Expected prehash components (in order):
  //   1. Prehash start byte = 0xff
  //   2. Key id = 0x00000315
  //   3. Reversed input string
  EXPECT_THAT(
      (*prehash_set_primitive)->Compute("abcde"),
      IsOkAndHolds(absl::StrCat(HexDecodeOrDie("ff00000315"), "edcba")));
}

TEST(PrehashWrapperTest, WrapWithLegacyPrimary) {
  KeysetInfo::KeyInfo* key_info;
  KeysetInfo keyset_info;

  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::WITH_ID_REQUIREMENT);
  key_info->set_key_id(0x7b);
  key_info->set_status(KeyStatusType::ENABLED);

  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::LEGACY);
  key_info->set_key_id(0x1c8);
  key_info->set_status(KeyStatusType::ENABLED);

  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_key_id(0x315);
  key_info->set_status(KeyStatusType::ENABLED);

  PrimitiveSet<Prehash>::Builder prehash_set_builder;
  prehash_set_builder.AddPrimitive(std::make_unique<ReverseHash>(),
                                   keyset_info.key_info(0));
  // Primary prehash primitive has key id 0x1c8 (from above).
  prehash_set_builder.AddPrimaryPrimitive(std::make_unique<ReverseHash>(),
                                          keyset_info.key_info(1));
  prehash_set_builder.AddPrimitive(std::make_unique<ReverseHash>(),
                                   keyset_info.key_info(2));
  absl::StatusOr<PrimitiveSet<Prehash>> prehash_set =
      std::move(prehash_set_builder).Build();
  ASSERT_THAT(prehash_set, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehash_set_primitive =
      PrehashWrapper().Wrap(
          std::make_unique<PrimitiveSet<Prehash>>(*std::move(prehash_set)));
  ASSERT_THAT(prehash_set_primitive, IsOk());

  // Expected prehash components (in order):
  //   1. Prehash start byte = 0xff
  //   2. Key id = 0x000001c8
  //   3. Reversed input string (legacy keys append 0x00 byte to input)
  EXPECT_THAT((*prehash_set_primitive)->Compute("abcde"),
              IsOkAndHolds(absl::StrCat(HexDecodeOrDie("ff000001c8"),
                                        HexDecodeOrDie("00"), "edcba")));
}

TEST(PrehashWrapperTest, WrapWithWithIdRequirementPrimary) {
  KeysetInfo::KeyInfo* key_info;
  KeysetInfo keyset_info;

  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::WITH_ID_REQUIREMENT);
  key_info->set_key_id(0x7b);
  key_info->set_status(KeyStatusType::ENABLED);

  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::LEGACY);
  key_info->set_key_id(0x1c8);
  key_info->set_status(KeyStatusType::ENABLED);

  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_key_id(0x315);
  key_info->set_status(KeyStatusType::ENABLED);

  PrimitiveSet<Prehash>::Builder prehash_set_builder;
  // Primary prehash primitive has key id 0x7b (from above).
  prehash_set_builder.AddPrimaryPrimitive(std::make_unique<ReverseHash>(),
                                          keyset_info.key_info(0));
  prehash_set_builder.AddPrimitive(std::make_unique<ReverseHash>(),
                                   keyset_info.key_info(1));
  prehash_set_builder.AddPrimitive(std::make_unique<ReverseHash>(),
                                   keyset_info.key_info(2));
  absl::StatusOr<PrimitiveSet<Prehash>> prehash_set =
      std::move(prehash_set_builder).Build();
  ASSERT_THAT(prehash_set, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehash_set_primitive =
      PrehashWrapper().Wrap(
          std::make_unique<PrimitiveSet<Prehash>>(*std::move(prehash_set)));
  ASSERT_THAT(prehash_set_primitive, IsOk());

  // Expected prehash components (in order):
  //   1. Prehash start byte = 0xff
  //   2. Key id = 0x0000007b
  //   3. Reversed input string
  EXPECT_THAT(
      (*prehash_set_primitive)->Compute("abcde"),
      IsOkAndHolds(absl::StrCat(HexDecodeOrDie("ff0000007b"), "edcba")));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
