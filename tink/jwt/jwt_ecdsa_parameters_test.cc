// Copyright 2024 Google LLC
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

#include "tink/jwt/jwt_ecdsa_parameters.h"

#include <tuple>

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
using ::testing::Combine;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

struct KidStrategyTuple {
  JwtEcdsaParameters::KidStrategy kid_strategy;
  bool allowed_kid_absent;
  bool has_id_requirement;
};

using JwtEcdsaParametersTest =
    TestWithParam<std::tuple<KidStrategyTuple, JwtEcdsaParameters::Algorithm>>;

INSTANTIATE_TEST_SUITE_P(
    JwtEcdsaParametersTestSuite, JwtEcdsaParametersTest,
    Combine(Values(
                KidStrategyTuple{
                    JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
                    /*allowed_kid_absent=*/false, /*has_id_requirement=*/true},
                KidStrategyTuple{JwtEcdsaParameters::KidStrategy::kCustom,
                                 /*allowed_kid_absent=*/true,
                                 /*has_id_requirement=*/false},
                KidStrategyTuple{JwtEcdsaParameters::KidStrategy::kIgnored,
                                 /*allowed_kid_absent=*/true,
                                 /*has_id_requirement=*/false}),
            Values(JwtEcdsaParameters::Algorithm::kEs256,
                   JwtEcdsaParameters::Algorithm::kEs384,
                   JwtEcdsaParameters::Algorithm::kEs512)));

TEST_P(JwtEcdsaParametersTest, Create) {
  KidStrategyTuple tuple;
  JwtEcdsaParameters::Algorithm algorithm;
  std::tie(tuple, algorithm) = GetParam();

  util::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(tuple.kid_strategy, algorithm);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetKidStrategy(), Eq(tuple.kid_strategy));
  EXPECT_THAT(parameters->GetAlgorithm(), Eq(algorithm));
  EXPECT_THAT(parameters->AllowKidAbsent(), Eq(tuple.allowed_kid_absent));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(tuple.has_id_requirement));
}

TEST(JwtEcdsaParametersTest, CreateWithInvalidKidStrategyFails) {
  EXPECT_THAT(JwtEcdsaParameters::Create(
                  JwtEcdsaParameters::KidStrategy::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements,
                  JwtEcdsaParameters::Algorithm::kEs512)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("unknown kid strategy")));
}

TEST(JwtEcdsaParametersTest, CreateWithInvalidAlgorithmFails) {
  EXPECT_THAT(JwtEcdsaParameters::Create(
                  JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
                  JwtEcdsaParameters::Algorithm::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("unknown algorithm")));
}

TEST(JwtEcdsaParametersTest, CopyConstructor) {
  util::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs512);
  ASSERT_THAT(parameters, IsOk());

  JwtEcdsaParameters copy(*parameters);

  EXPECT_THAT(copy.GetKidStrategy(), Eq(parameters->GetKidStrategy()));
  EXPECT_THAT(copy.GetAlgorithm(), Eq(parameters->GetAlgorithm()));
  EXPECT_THAT(copy.AllowKidAbsent(), Eq(parameters->AllowKidAbsent()));
  EXPECT_THAT(copy.HasIdRequirement(), Eq(parameters->HasIdRequirement()));
}

TEST(JwtEcdsaParametersTest, CopyAssignment) {
  util::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs512);
  ASSERT_THAT(parameters, IsOk());

  JwtEcdsaParameters copy = *parameters;

  EXPECT_THAT(copy.GetKidStrategy(), Eq(parameters->GetKidStrategy()));
  EXPECT_THAT(copy.GetAlgorithm(), Eq(parameters->GetAlgorithm()));
  EXPECT_THAT(copy.AllowKidAbsent(), Eq(parameters->AllowKidAbsent()));
  EXPECT_THAT(copy.HasIdRequirement(), Eq(parameters->HasIdRequirement()));
}

TEST_P(JwtEcdsaParametersTest, ParametersEquals) {
  KidStrategyTuple tuple;
  JwtEcdsaParameters::Algorithm algorithm;
  std::tie(tuple, algorithm) = GetParam();

  util::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(tuple.kid_strategy, algorithm);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<JwtEcdsaParameters> other_parameters =
      JwtEcdsaParameters::Create(tuple.kid_strategy, algorithm);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(JwtEcdsaParametersTest, KidStrategyNotEqual) {
  util::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<JwtEcdsaParameters> other_parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kCustom,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(JwtEcdsaParametersTest, AlgorithmNotEqual) {
  util::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<JwtEcdsaParameters> other_parameters =
      JwtEcdsaParameters::Create(
          JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
          JwtEcdsaParameters::Algorithm::kEs384);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
