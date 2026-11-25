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

#include "tink/daead/internal/aes_siv_key_creator.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/daead/aes_siv_key.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/daead/internal/aes_siv_test_vectors.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"

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
  const AesSivKey& expected_key;
};

using AesSivKeyCreatorParameterizedTest = TestWithParam<TestCase>;

TEST_P(AesSivKeyCreatorParameterizedTest, CreateKeyWorks) {
  const AesSivKey& expected_key = GetParam().expected_key;

  absl::StatusOr<std::unique_ptr<Key>> key = CreateAesSivKey(
      expected_key.GetParameters(), expected_key.GetIdRequirement());
  ASSERT_THAT(key, IsOk());

  const auto* aes_siv_key = dynamic_cast<const AesSivKey*>(key->get());
  ASSERT_NE(aes_siv_key, nullptr);
  EXPECT_THAT(aes_siv_key->GetIdRequirement(),
              Eq(expected_key.GetIdRequirement()));
  EXPECT_THAT(aes_siv_key->GetParameters(), Eq(expected_key.GetParameters()));
  EXPECT_THAT(aes_siv_key->GetOutputPrefix(),
              Eq(expected_key.GetOutputPrefix()));
}

TEST_P(AesSivKeyCreatorParameterizedTest, CreateKeyTwiceYieldsDifferentKeys) {
  const AesSivKey& expected_key = GetParam().expected_key;

  absl::StatusOr<std::unique_ptr<Key>> key1 = CreateAesSivKey(
      expected_key.GetParameters(), expected_key.GetIdRequirement());
  ASSERT_THAT(key1, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> key2 = CreateAesSivKey(
      expected_key.GetParameters(), expected_key.GetIdRequirement());
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(**key1, **key2);
}

TEST_P(AesSivKeyCreatorParameterizedTest,
       CreateKeyWithKeyGenConfigurationWorks) {
  const AesSivKey& expected_key = GetParam().expected_key;
  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddKeyCreator<AesSivParameters>(
                  CreateAesSivKey, key_creator_config),
              IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key = KeyGenConfigurationImpl::CreateKey(
      expected_key.GetParameters(), expected_key.GetIdRequirement(),
      key_creator_config);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetParameters(), Eq(expected_key.GetParameters()));
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(expected_key.GetIdRequirement()));
}

INSTANTIATE_TEST_SUITE_P(
    AesSivKeyCreatorParameterizedTests, AesSivKeyCreatorParameterizedTest,
    ValuesIn<TestCase>({
        {/*name=*/"AesSiv32NoPrefix",
         /*expected_key=*/GetAesSivTestVector(
             32, AesSivParameters::Variant::kNoPrefix)
             .key},
        {/*name=*/"AesSiv32Tink",
         /*expected_key=*/GetAesSivTestVector(32,
                                              AesSivParameters::Variant::kTink)
             .key},
        {/*name=*/"AesSiv48Crunchy",
         /*expected_key=*/GetAesSivTestVector(
             48, AesSivParameters::Variant::kCrunchy)
             .key},
        {/*name=*/"AesSiv64Tink",
         /*expected_key=*/GetAesSivTestVector(64,
                                              AesSivParameters::Variant::kTink)
             .key},
        {/*name=*/"AesSiv64NoPrefix",
         /*expected_key=*/GetAesSivTestVector(
             64, AesSivParameters::Variant::kNoPrefix)
             .key},
    }),
    [](const TestParamInfo<TestCase>& info) { return info.param.name; });

TEST(AesSivKeyCreatorTest, CreateKeyTinkWithoutIdRequirementFails) {
  const AesSivParameters& tink_params =
      GetAesSivTestVector(64, AesSivParameters::Variant::kTink)
          .key.GetParameters();
  EXPECT_THAT(CreateAesSivKey(tink_params, std::nullopt),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesSivKeyCreatorTest, CreateKeyNoPrefixWithIdRequirementFails) {
  const AesSivParameters& no_prefix_params =
      GetAesSivTestVector(64, AesSivParameters::Variant::kNoPrefix)
          .key.GetParameters();
  EXPECT_THAT(CreateAesSivKey(no_prefix_params, 123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
