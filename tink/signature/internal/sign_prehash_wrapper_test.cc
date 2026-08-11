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

#include "tink/signature/internal/sign_prehash_wrapper.h"

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
#include "tink/signature/sign_prehash.h"
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

TEST(SignPrehashWrapperTest, WrapNullPtr) {
  EXPECT_THAT(SignPrehashWrapper().Wrap(nullptr).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignPrehashWrapperTest, WrapEmpty) {
  auto prehash_sign_set = std::make_unique<PrimitiveSet<SignPrehash>>();
  EXPECT_THAT(SignPrehashWrapper().Wrap(std::move(prehash_sign_set)).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

class ReverseSign : public SignPrehash {
 public:
  absl::StatusOr<std::string> Sign(absl::string_view prehash) const override {
    std::string output = std::string(prehash);
    absl::c_reverse(output);
    return output;
  }
};

TEST(SignPrehashWrapperTest, WrapWithRawPrimitiveNotAllowed) {
  KeysetInfo::KeyInfo* key_info;
  KeysetInfo keyset_info;

  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::RAW);
  key_info->set_key_id(0x7b);
  key_info->set_status(KeyStatusType::ENABLED);

  PrimitiveSet<SignPrehash>::Builder sign_set_builder;
  sign_set_builder.AddPrimaryPrimitive(std::make_unique<ReverseSign>(),
                                       keyset_info.key_info(0));
  absl::StatusOr<PrimitiveSet<SignPrehash>> sign_set =
      std::move(sign_set_builder).Build();
  ASSERT_THAT(sign_set, IsOk());

  absl::StatusOr<std::unique_ptr<SignPrehash>> sign_set_primitive =
      SignPrehashWrapper().Wrap(
          std::make_unique<PrimitiveSet<SignPrehash>>(*std::move(sign_set)));
  EXPECT_THAT(sign_set_primitive.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SignPrehashWrapperTest, WrapWithTinkPrimary) {
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

  PrimitiveSet<SignPrehash>::Builder sign_set_builder;
  sign_set_builder.AddPrimitive(std::make_unique<ReverseSign>(),
                                keyset_info.key_info(0));
  sign_set_builder.AddPrimitive(std::make_unique<ReverseSign>(),
                                keyset_info.key_info(1));
  // Primary prehash sign primitive has key id 0x315 (from above).
  sign_set_builder.AddPrimaryPrimitive(std::make_unique<ReverseSign>(),
                                       keyset_info.key_info(2));
  absl::StatusOr<PrimitiveSet<SignPrehash>> sign_set =
      std::move(sign_set_builder).Build();
  ASSERT_THAT(sign_set, IsOk());

  absl::StatusOr<std::unique_ptr<SignPrehash>> sign_set_primitive =
      SignPrehashWrapper().Wrap(
          std::make_unique<PrimitiveSet<SignPrehash>>(*std::move(sign_set)));
  ASSERT_THAT(sign_set_primitive, IsOk());

  // Expected signature components (in order):
  //   1. Tink start byte = 0x01
  //   2. Key id = 0x00000315
  //   3. Reversed input string
  std::string prehash_prefix = HexDecodeOrDie("ff00000315");
  std::string signature_prefix = HexDecodeOrDie("0100000315");
  EXPECT_THAT(
      (*sign_set_primitive)->Sign(absl::StrCat(prehash_prefix, "abcde")),
      IsOkAndHolds(absl::StrCat(signature_prefix, "edcba")));
}

TEST(SignPrehashWrapperTest, WrapWithLegacyPrimary) {
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

  PrimitiveSet<SignPrehash>::Builder sign_set_builder;
  sign_set_builder.AddPrimitive(std::make_unique<ReverseSign>(),
                                keyset_info.key_info(0));
  // Primary prehash sign primitive has key id 0x1c8 (from above).
  sign_set_builder.AddPrimaryPrimitive(std::make_unique<ReverseSign>(),
                                       keyset_info.key_info(1));
  sign_set_builder.AddPrimitive(std::make_unique<ReverseSign>(),
                                keyset_info.key_info(2));
  absl::StatusOr<PrimitiveSet<SignPrehash>> sign_set =
      std::move(sign_set_builder).Build();
  ASSERT_THAT(sign_set, IsOk());

  absl::StatusOr<std::unique_ptr<SignPrehash>> sign_set_primitive =
      SignPrehashWrapper().Wrap(
          std::make_unique<PrimitiveSet<SignPrehash>>(*std::move(sign_set)));
  ASSERT_THAT(sign_set_primitive, IsOk());

  // Expected signature components (in order):
  //   1. Legacy start byte = 0x00
  //   2. Key id = 0x000001c8
  //   3. Reversed input string
  std::string prehash_prefix = HexDecodeOrDie("ff000001c8");
  std::string signature_prefix = HexDecodeOrDie("00000001c8");
  EXPECT_THAT(
      (*sign_set_primitive)->Sign(absl::StrCat(prehash_prefix, "abcde")),
      IsOkAndHolds(absl::StrCat(signature_prefix, "edcba")));
}

TEST(SignPrehashWrapperTest, WrapWithWithIdRequirementPrimary) {
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

  PrimitiveSet<SignPrehash>::Builder sign_set_builder;
  // Primary prehash sign primitive has key id 0x7b (from above).
  sign_set_builder.AddPrimaryPrimitive(std::make_unique<ReverseSign>(),
                                       keyset_info.key_info(0));
  sign_set_builder.AddPrimitive(std::make_unique<ReverseSign>(),
                                keyset_info.key_info(1));
  sign_set_builder.AddPrimitive(std::make_unique<ReverseSign>(),
                                keyset_info.key_info(2));
  absl::StatusOr<PrimitiveSet<SignPrehash>> sign_set =
      std::move(sign_set_builder).Build();
  ASSERT_THAT(sign_set, IsOk());

  absl::StatusOr<std::unique_ptr<SignPrehash>> sign_set_primitive =
      SignPrehashWrapper().Wrap(
          std::make_unique<PrimitiveSet<SignPrehash>>(*std::move(sign_set)));
  ASSERT_THAT(sign_set_primitive, IsOk());

  std::string prehash_prefix = HexDecodeOrDie("ff0000007b");
  EXPECT_THAT(
      (*sign_set_primitive)->Sign(absl::StrCat(prehash_prefix, "abcde")),
      IsOkAndHolds("edcba"));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
