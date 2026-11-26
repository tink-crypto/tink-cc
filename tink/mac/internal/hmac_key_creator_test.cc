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

#include "tink/mac/internal/hmac_key_creator.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/mac/hmac_key.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/mac/internal/hmac_test_vectors.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::TestParamInfo;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

struct TestCase {
  std::string name;
  const HmacKey& expected_key;
};

using HmacKeyCreatorParameterizedTest = TestWithParam<TestCase>;

TEST_P(HmacKeyCreatorParameterizedTest, CreateKeyWorks) {
  const HmacKey& expected_key = GetParam().expected_key;

  absl::StatusOr<std::unique_ptr<Key>> key = CreateHmacKey(
      expected_key.GetParameters(), expected_key.GetIdRequirement());
  ASSERT_THAT(key, IsOk());

  const auto* hmac_key = dynamic_cast<const HmacKey*>(key->get());
  ASSERT_NE(hmac_key, nullptr);
  EXPECT_THAT(hmac_key->GetIdRequirement(),
              Eq(expected_key.GetIdRequirement()));
  EXPECT_THAT(hmac_key->GetParameters(), Eq(expected_key.GetParameters()));
  EXPECT_THAT(hmac_key->GetOutputPrefix(), Eq(expected_key.GetOutputPrefix()));
}

TEST_P(HmacKeyCreatorParameterizedTest, CreateKeyTwiceYieldsDifferentKeys) {
  const HmacKey& expected_key = GetParam().expected_key;

  absl::StatusOr<std::unique_ptr<Key>> key1 = CreateHmacKey(
      expected_key.GetParameters(), expected_key.GetIdRequirement());
  ASSERT_THAT(key1, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> key2 = CreateHmacKey(
      expected_key.GetParameters(), expected_key.GetIdRequirement());
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(**key1, **key2);
}

TEST_P(HmacKeyCreatorParameterizedTest, CreateKeyWithKeyGenConfigurationWorks) {
  const HmacKey& expected_key = GetParam().expected_key;
  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddKeyCreator<HmacParameters>(
                  CreateHmacKey, key_creator_config),
              IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key = KeyGenConfigurationImpl::CreateKey(
      expected_key.GetParameters(), expected_key.GetIdRequirement(),
      key_creator_config);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetParameters(), Eq(expected_key.GetParameters()));
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(expected_key.GetIdRequirement()));
}

INSTANTIATE_TEST_SUITE_P(
    HmacKeyCreatorParameterizedTests, HmacKeyCreatorParameterizedTest,
    ValuesIn<TestCase>({
        {/*name=*/"Hmac16Sha256NoPrefix",
         /*expected_key=*/GetHmacTestVector(16,
                                            HmacParameters::HashType::kSha256,
                                            HmacParameters::Variant::kNoPrefix)
             .key},
        {/*name=*/"Hmac40Sha256Tink",
         /*expected_key=*/GetHmacTestVector(40,
                                            HmacParameters::HashType::kSha256,
                                            HmacParameters::Variant::kTink)
             .key},
        {/*name=*/"Hmac20Sha384Crunchy",
         /*expected_key=*/GetHmacTestVector(20,
                                            HmacParameters::HashType::kSha384,
                                            HmacParameters::Variant::kCrunchy)
             .key},
        {/*name=*/"Hmac32Sha1Legacy",
         /*expected_key=*/GetHmacTestVector(32, HmacParameters::HashType::kSha1,
                                            HmacParameters::Variant::kLegacy)
             .key},
        {/*name=*/"Hmac100Sha512Tink",
         /*expected_key=*/GetHmacTestVector(100,
                                            HmacParameters::HashType::kSha512,
                                            HmacParameters::Variant::kTink)
             .key},
    }),
    [](const TestParamInfo<TestCase>& info) { return info.param.name; });

TEST(HmacKeyCreatorTest, CreateKeyTinkWithoutIdRequirementFails) {
  const HmacParameters& tink_params =
      GetHmacTestVector(40, HmacParameters::HashType::kSha256,
                        HmacParameters::Variant::kTink)
          .key.GetParameters();
  EXPECT_THAT(CreateHmacKey(tink_params, std::nullopt),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HmacKeyCreatorTest, CreateKeyNoPrefixWithIdRequirementFails) {
  const HmacParameters& no_prefix_params =
      GetHmacTestVector(16, HmacParameters::HashType::kSha256,
                        HmacParameters::Variant::kNoPrefix)
          .key.GetParameters();
  EXPECT_THAT(CreateHmacKey(no_prefix_params, 123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
