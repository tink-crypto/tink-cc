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

#include "tink/signature/composite_ml_dsa_parameters.h"

#include <memory>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/parameters.h"
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
  CompositeMlDsaParameters::MlDsaInstance ml_dsa_instance;
  CompositeMlDsaParameters::ClassicalAlgorithm classical_algorithm;
  CompositeMlDsaParameters::Variant variant;
  bool has_id_requirement;
};

using CompositeMlDsaParametersTest = TestWithParam<VariantTestCase>;

INSTANTIATE_TEST_SUITE_P(
    CompositeMlDsaParametersTestSuite, CompositeMlDsaParametersTest,
    Values(
        VariantTestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                        CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
                        CompositeMlDsaParameters::Variant::kTink,
                        /*has_id_requirement=*/true},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
            CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
            CompositeMlDsaParameters::Variant::kNoPrefix,
            /*has_id_requirement=*/false},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
            CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
            CompositeMlDsaParameters::Variant::kNoPrefix,
            /*has_id_requirement=*/false},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
            CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
            CompositeMlDsaParameters::Variant::kTink,
            /*has_id_requirement=*/true},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
            CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
            CompositeMlDsaParameters::Variant::kNoPrefix,
            /*has_id_requirement=*/false},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
            CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
            CompositeMlDsaParameters::Variant::kTink,
            /*has_id_requirement=*/true},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
            CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
            CompositeMlDsaParameters::Variant::kNoPrefix,
            /*has_id_requirement=*/false},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
            CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
            CompositeMlDsaParameters::Variant::kTink,
            /*has_id_requirement=*/true},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
            CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
            CompositeMlDsaParameters::Variant::kNoPrefix,
            /*has_id_requirement=*/false},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
            CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
            CompositeMlDsaParameters::Variant::kTink,
            /*has_id_requirement=*/true},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
            CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1,
            CompositeMlDsaParameters::Variant::kNoPrefix,
            /*has_id_requirement=*/false},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
            CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1,
            CompositeMlDsaParameters::Variant::kTink,
            /*has_id_requirement=*/true},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
            CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1,
            CompositeMlDsaParameters::Variant::kNoPrefix,
            /*has_id_requirement=*/false},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
            CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1,
            CompositeMlDsaParameters::Variant::kTink,
            /*has_id_requirement=*/true},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
            CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
            CompositeMlDsaParameters::Variant::kNoPrefix,
            /*has_id_requirement=*/false},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
            CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
            CompositeMlDsaParameters::Variant::kTink,
            /*has_id_requirement=*/true},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
            CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
            CompositeMlDsaParameters::Variant::kNoPrefix,
            /*has_id_requirement=*/false},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
            CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
            CompositeMlDsaParameters::Variant::kTink,
            /*has_id_requirement=*/true},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
            CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
            CompositeMlDsaParameters::Variant::kNoPrefix,
            /*has_id_requirement=*/false},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
            CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
            CompositeMlDsaParameters::Variant::kTink,
            /*has_id_requirement=*/true},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
            CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
            CompositeMlDsaParameters::Variant::kNoPrefix,
            /*has_id_requirement=*/false},
        VariantTestCase{
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
            CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
            CompositeMlDsaParameters::Variant::kTink,
            /*has_id_requirement=*/true}));

TEST_P(CompositeMlDsaParametersTest, CreateCompositeMlDsaWorks) {
  VariantTestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetMlDsaInstance(), Eq(test_case.ml_dsa_instance));
  EXPECT_THAT(parameters->GetClassicalAlgorithm(),
              Eq(test_case.classical_algorithm));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST_P(CompositeMlDsaParametersTest, CreateWithInvalidMlDsaInstanceFails) {
  VariantTestCase test_case = GetParam();

  EXPECT_THAT(CompositeMlDsaParameters::Create(
                  CompositeMlDsaParameters::MlDsaInstance::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements,
                  test_case.classical_algorithm, test_case.variant)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(CompositeMlDsaParametersTest, CreateWithInvalidClassicalAlgorithmFails) {
  VariantTestCase test_case = GetParam();

  EXPECT_THAT(CompositeMlDsaParameters::Create(
                  test_case.ml_dsa_instance,
                  CompositeMlDsaParameters::ClassicalAlgorithm::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements,
                  test_case.variant)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(CompositeMlDsaParametersTest, CreateWithInvalidVariantFails) {
  VariantTestCase test_case = GetParam();

  EXPECT_THAT(CompositeMlDsaParameters::Create(
                  test_case.ml_dsa_instance, test_case.classical_algorithm,
                  CompositeMlDsaParameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CompositeMlDsaParametersTest, CopyConstructor) {
  {
    absl::StatusOr<CompositeMlDsaParameters> parameters =
        CompositeMlDsaParameters::Create(
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
            CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
            CompositeMlDsaParameters::Variant::kTink);
    ASSERT_THAT(parameters, IsOk());

    CompositeMlDsaParameters copy(*parameters);

    EXPECT_THAT(copy, Eq(*parameters));
  }
  {
    absl::StatusOr<CompositeMlDsaParameters> parameters =
        CompositeMlDsaParameters::Create(
            CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
            CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
            CompositeMlDsaParameters::Variant::kNoPrefix);
    ASSERT_THAT(parameters, IsOk());

    CompositeMlDsaParameters copy(*parameters);

    EXPECT_THAT(copy, Eq(*parameters));
  }
}

TEST(CompositeMlDsaParametersTest, CopyAssignment) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<CompositeMlDsaParameters> copy =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(copy, IsOk());

  *copy = *parameters;

  EXPECT_THAT(*copy, Eq(*parameters));
}

TEST(CompositeMlDsaParametersTest, MoveConstructor) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaParameters expected(*parameters);
  CompositeMlDsaParameters moved(std::move(*parameters));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(CompositeMlDsaParametersTest, MoveAssignment) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<CompositeMlDsaParameters> moved =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(moved, IsOk());

  CompositeMlDsaParameters expected(*parameters);
  *moved = std::move(*parameters);

  EXPECT_THAT(*moved, Eq(expected));
}

TEST_P(CompositeMlDsaParametersTest, ParametersEquals) {
  VariantTestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameter =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
  ASSERT_THAT(parameter, IsOk());

  absl::StatusOr<CompositeMlDsaParameters> other_parameter =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
  ASSERT_THAT(other_parameter, IsOk());

  EXPECT_TRUE(*parameter == *other_parameter);
  EXPECT_TRUE(*other_parameter == *parameter);
  EXPECT_FALSE(*parameter != *other_parameter);
  EXPECT_FALSE(*other_parameter != *parameter);
}

TEST(CompositeMlDsaParametersTest, DifferentMlDsaInstanceNotEqual) {
  absl::StatusOr<CompositeMlDsaParameters> parameter =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameter, IsOk());

  absl::StatusOr<CompositeMlDsaParameters> other_parameter =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
          CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(other_parameter, IsOk());

  EXPECT_TRUE(*parameter != *other_parameter);
  EXPECT_FALSE(*parameter == *other_parameter);
}

TEST_P(CompositeMlDsaParametersTest, DifferentClassicalAlgorithmNotEqual) {
  VariantTestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameter =
      CompositeMlDsaParameters::Create(
          test_case.ml_dsa_instance,
          CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
          test_case.variant);
  ASSERT_THAT(parameter, IsOk());

  absl::StatusOr<CompositeMlDsaParameters> other_parameter =
      CompositeMlDsaParameters::Create(
          test_case.ml_dsa_instance,
          CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
          test_case.variant);
  ASSERT_THAT(other_parameter, IsOk());

  EXPECT_TRUE(*parameter != *other_parameter);
  EXPECT_FALSE(*parameter == *other_parameter);
}

TEST_P(CompositeMlDsaParametersTest, DifferentVariantNotEqual) {
  VariantTestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameter =
      CompositeMlDsaParameters::Create(
          test_case.ml_dsa_instance, test_case.classical_algorithm,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameter, IsOk());

  absl::StatusOr<CompositeMlDsaParameters> other_parameter =
      CompositeMlDsaParameters::Create(
          test_case.ml_dsa_instance, test_case.classical_algorithm,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(other_parameter, IsOk());

  EXPECT_TRUE(*parameter != *other_parameter);
  EXPECT_FALSE(*parameter == *other_parameter);
}

TEST(CompositeMlDsaParametersTest, Clone) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  ASSERT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
