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

#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::TestWithParam;
using ::testing::Values;

struct VariantTestCase {
  MlKemParameters::Variant variant;
  bool has_id_requirement;
};

using MlKemParametersTest = TestWithParam<VariantTestCase>;

// Note: for now only the Tink variant is supported, so this test suite should
// be extended if other variants (e.g. no-prefix) are added in the future.
INSTANTIATE_TEST_SUITE_P(MlKemParametersTestSuite, MlKemParametersTest,
                         Values(VariantTestCase{MlKemParameters::Variant::kTink,
                                                /*has_id_requirement=*/true}));

TEST_P(MlKemParametersTest, CreateMlKem768Works) {
  VariantTestCase test_case = GetParam();

  absl::StatusOr<MlKemParameters> parameters =
      MlKemParameters::Create(/*key_size=*/768, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetKeySize(), Eq(768));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST_P(MlKemParametersTest, CreateMlKem512IsntSupported) {
  VariantTestCase test_case = GetParam();

  EXPECT_THAT(
      MlKemParameters::Create(/*key_size=*/512, test_case.variant).status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(MlKemParametersTest, CreateMlKem1024IsntSupported) {
  VariantTestCase test_case = GetParam();

  EXPECT_THAT(
      MlKemParameters::Create(/*key_size=*/1024, test_case.variant).status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MlKemParametersTest, CreateWithInvalidVariantFails) {
  EXPECT_THAT(MlKemParameters::Create(
                  /*key_size=*/768,
                  MlKemParameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MlKemParametersTest, CopyConstructor) {
  absl::StatusOr<MlKemParameters> parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  MlKemParameters copy(*parameters);

  EXPECT_THAT(copy.GetKeySize(), Eq(768));
  EXPECT_THAT(copy.GetVariant(), Eq(MlKemParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST(MlKemParametersTest, CopyAssignment) {
  absl::StatusOr<MlKemParameters> parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  MlKemParameters copy = *parameters;

  EXPECT_THAT(copy.GetKeySize(), Eq(768));
  EXPECT_THAT(copy.GetVariant(), Eq(MlKemParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST(MlKemParametersTest, ParametersEquals) {
  absl::StatusOr<MlKemParameters> parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<MlKemParameters> other_parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(MlKemParametersTest, Clone) {
  absl::StatusOr<MlKemParameters> parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  ASSERT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
