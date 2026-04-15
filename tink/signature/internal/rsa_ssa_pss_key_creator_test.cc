// Copyright 2026 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/internal/rsa_ssa_pss_key_creator.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_proto_serialization.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using KeyCreatorsTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    KeyCreatorsTestSuite, KeyCreatorsTest,
    Values(TestCase{0x02030400, std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{absl::nullopt, ""}));

TEST_P(KeyCreatorsTest, CreateRsaSsaPssPrivateKeyWorks) {
  TestCase test_case = GetParam();

  RsaSsaPssParameters::Variant variant =
      test_case.id_requirement.has_value()
          ? RsaSsaPssParameters::Variant::kTink
          : RsaSsaPssParameters::Variant::kNoPrefix;
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<RsaSsaPssPrivateKey>> private_key =
      CreateRsaSsaPssKey(*parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT((*private_key)->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT((*private_key)->GetIdRequirement(), Eq(test_case.id_requirement));
}

TEST_P(KeyCreatorsTest, CreateRsaSsaPssPrivateKeyTwiceYieldsDifferentKeys) {
  TestCase test_case = GetParam();

  RsaSsaPssParameters::Variant variant =
      test_case.id_requirement.has_value()
          ? RsaSsaPssParameters::Variant::kTink
          : RsaSsaPssParameters::Variant::kNoPrefix;
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<RsaSsaPssPrivateKey>> private_key1 =
      CreateRsaSsaPssKey(*parameters, test_case.id_requirement);
  ASSERT_THAT(private_key1, IsOk());

  absl::StatusOr<std::unique_ptr<RsaSsaPssPrivateKey>> private_key2 =
      CreateRsaSsaPssKey(*parameters, test_case.id_requirement);
  ASSERT_THAT(private_key2, IsOk());

  EXPECT_THAT(**private_key1, Not(Eq(**private_key2)));
}

TEST_P(KeyCreatorsTest, CreateKeysetHandleFromConfigWithRsaSsaPssKeyWorks) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());
  TestCase test_case = GetParam();

  RsaSsaPssParameters::Variant variant =
      test_case.id_requirement.has_value()
          ? RsaSsaPssParameters::Variant::kTink
          : RsaSsaPssParameters::Variant::kNoPrefix;
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(
      internal::KeyGenConfigurationImpl::AddKeyCreator<RsaSsaPssParameters>(
          CreateRsaSsaPssKey, key_creator_config),
      IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/123);
  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry))
                                            .Build(key_creator_config);
  ASSERT_THAT(handle.status(), IsOk());

  EXPECT_THAT(*handle, SizeIs(1));
  EXPECT_THAT((*handle)[0].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*handle)[0].GetId(), Eq(123));
  EXPECT_THAT((*handle)[0].IsPrimary(), IsTrue());
  EXPECT_THAT((*handle)[0].GetKey()->GetParameters(), Eq(*parameters));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
