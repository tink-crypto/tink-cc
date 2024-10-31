// Copyright 2024 Google LLC
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

#include "tink/signature/ml_dsa_parameters.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::Values;

struct VariantTestCase {
  MlDsaParameters::Variant variant;
  bool has_id_requirement;
};

using MlDsaParametersTest = TestWithParam<VariantTestCase>;

// Note: for now only the Tink variant is supported, so this test suite should
// be extended if other variants (e.g. no-prefix) are added in the future.
INSTANTIATE_TEST_SUITE_P(
    MlDsaParametersTestSuite, MlDsaParametersTest,
    Values(VariantTestCase{MlDsaParameters::Variant::kNoPrefix,
                           /*has_id_requirement=*/false},
           VariantTestCase{MlDsaParameters::Variant::kTink,
                           /*has_id_requirement=*/true}));

TEST_P(MlDsaParametersTest, CreateMlDsa65Works) {
  VariantTestCase test_case = GetParam();

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetInstance(),
              Eq(MlDsaParameters::Instance::kMlDsa65));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(MlDsaParametersTest, CreateWithInvalidVariantFails) {
  EXPECT_THAT(MlDsaParameters::Create(
                  MlDsaParameters::Instance::kMlDsa65,
                  MlDsaParameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MlDsaParametersTest, CreateWithInvalidInstanceFails) {
  EXPECT_THAT(MlDsaParameters::Create(
                  MlDsaParameters::Instance::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements,
                  MlDsaParameters::Variant::kTink)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(MlDsaParametersTest, CopyConstructor) {
  VariantTestCase test_case = GetParam();

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  MlDsaParameters copy(*parameters);

  EXPECT_THAT(copy.GetInstance(), Eq(MlDsaParameters::Instance::kMlDsa65));
  EXPECT_THAT(copy.GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(copy.HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST_P(MlDsaParametersTest, CopyAssignment) {
  VariantTestCase test_case = GetParam();

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  MlDsaParameters copy = *parameters;

  EXPECT_THAT(copy.GetInstance(), Eq(MlDsaParameters::Instance::kMlDsa65));
  EXPECT_THAT(copy.GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(copy.HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST_P(MlDsaParametersTest, ParametersEquals) {
  VariantTestCase test_case = GetParam();

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<MlDsaParameters> other_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(MlDsaParametersTest, DifferentVariantNotEqual) {
  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kNoPrefix);

  util::StatusOr<MlDsaParameters> other_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
