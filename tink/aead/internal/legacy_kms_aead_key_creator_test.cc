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

#include "tink/aead/internal/legacy_kms_aead_key_creator.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/aead/legacy_kms_aead_key.h"
#include "tink/aead/legacy_kms_aead_parameters.h"
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

constexpr absl::string_view kKeyUri = "some://arbitrary.key.uri";

const LegacyKmsAeadParameters& LegacyKmsAeadTinkParameters() {
  static const absl::NoDestructor<LegacyKmsAeadParameters> kParameters([] {
    absl::StatusOr<LegacyKmsAeadParameters> parameters =
        LegacyKmsAeadParameters::Create(
            kKeyUri, LegacyKmsAeadParameters::Variant::kTink);
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

const LegacyKmsAeadParameters& LegacyKmsAeadNoPrefixParameters() {
  static const absl::NoDestructor<LegacyKmsAeadParameters> kParameters([] {
    absl::StatusOr<LegacyKmsAeadParameters> parameters =
        LegacyKmsAeadParameters::Create(
            kKeyUri, LegacyKmsAeadParameters::Variant::kNoPrefix);
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

struct TestCase {
  std::string name;
  const LegacyKmsAeadParameters& parameters;
  std::optional<int> id_requirement;
  std::string expected_output_prefix;
};

using LegacyKmsAeadKeyCreatorParameterizedTest = TestWithParam<TestCase>;

TEST_P(LegacyKmsAeadKeyCreatorParameterizedTest, CreateKeyWorks) {
  const TestCase& test_case = GetParam();

  absl::StatusOr<std::unique_ptr<Key>> key =
      CreateLegacyKmsAeadKey(test_case.parameters, test_case.id_requirement);
  ASSERT_THAT(key, IsOk());

  const auto* kms_key = dynamic_cast<const LegacyKmsAeadKey*>(key->get());
  ASSERT_NE(kms_key, nullptr);
  EXPECT_THAT(kms_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(kms_key->GetParameters(), Eq(test_case.parameters));
  EXPECT_THAT(kms_key->GetOutputPrefix(), Eq(test_case.expected_output_prefix));
}

TEST_P(LegacyKmsAeadKeyCreatorParameterizedTest,
       CreateKeyWithKeyGenConfigurationWorks) {
  const TestCase& test_case = GetParam();
  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddKeyCreator<LegacyKmsAeadParameters>(
                  CreateLegacyKmsAeadKey, key_creator_config),
              IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key = KeyGenConfigurationImpl::CreateKey(
      test_case.parameters, test_case.id_requirement, key_creator_config);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetParameters(), Eq(test_case.parameters));
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id_requirement));
}

INSTANTIATE_TEST_SUITE_P(
    LegacyKmsAeadKeyCreatorParameterizedTests,
    LegacyKmsAeadKeyCreatorParameterizedTest,
    ValuesIn<TestCase>({
        {/*name=*/"LegacyKmsAeadTink",
         /*parameters=*/LegacyKmsAeadTinkParameters(),
         /*id_requirement=*/0x02030400,
         /*expected_output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
        {/*name=*/"LegacyKmsAeadNoPrefix",
         /*parameters=*/LegacyKmsAeadNoPrefixParameters(),
         /*id_requirement=*/std::nullopt,
         /*expected_output_prefix=*/""},
    }),
    [](const TestParamInfo<TestCase>& info) { return info.param.name; });

TEST(LegacyKmsAeadKeyCreatorTest, CreateKeyTinkWithoutIdRequirementFails) {
  EXPECT_THAT(
      CreateLegacyKmsAeadKey(LegacyKmsAeadTinkParameters(), std::nullopt),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(LegacyKmsAeadKeyCreatorTest, CreateKeyNoPrefixWithIdRequirementFails) {
  EXPECT_THAT(CreateLegacyKmsAeadKey(LegacyKmsAeadNoPrefixParameters(), 123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
