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

#include "tink/jwt/jwt_ml_dsa_parameters.h"

#include <memory>
#include <tuple>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/parameters.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Combine;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

struct KidStrategyTuple {
  JwtMlDsaParameters::KidStrategy kid_strategy;
  bool allowed_kid_absent;
  bool has_id_requirement;
};

using JwtMlDsaParametersTest =
    TestWithParam<std::tuple<KidStrategyTuple, JwtMlDsaParameters::Algorithm>>;

INSTANTIATE_TEST_SUITE_P(
    JwtMlDsaParametersTestSuite, JwtMlDsaParametersTest,
    Combine(Values(
                KidStrategyTuple{
                    JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
                    /*allowed_kid_absent=*/false, /*has_id_requirement=*/true},
                KidStrategyTuple{JwtMlDsaParameters::KidStrategy::kCustom,
                                 /*allowed_kid_absent=*/true,
                                 /*has_id_requirement=*/false},
                KidStrategyTuple{JwtMlDsaParameters::KidStrategy::kIgnored,
                                 /*allowed_kid_absent=*/true,
                                 /*has_id_requirement=*/false}),
            Values(JwtMlDsaParameters::Algorithm::kMlDsa44,
                   JwtMlDsaParameters::Algorithm::kMlDsa65,
                   JwtMlDsaParameters::Algorithm::kMlDsa87)));

TEST_P(JwtMlDsaParametersTest, Create) {
  KidStrategyTuple tuple;
  JwtMlDsaParameters::Algorithm algorithm;
  std::tie(tuple, algorithm) = GetParam();

  absl::StatusOr<JwtMlDsaParameters> parameters =
      JwtMlDsaParameters::Create(tuple.kid_strategy, algorithm);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetKidStrategy(), Eq(tuple.kid_strategy));
  EXPECT_THAT(parameters->GetAlgorithm(), Eq(algorithm));
  EXPECT_THAT(parameters->AllowKidAbsent(), Eq(tuple.allowed_kid_absent));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(tuple.has_id_requirement));
}

TEST(JwtMlDsaParametersTest, CreateWithInvalidKidStrategyFails) {
  EXPECT_THAT(JwtMlDsaParameters::Create(
                  JwtMlDsaParameters::KidStrategy::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements,
                  JwtMlDsaParameters::Algorithm::kMlDsa87)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("unknown kid strategy")));
}

TEST(JwtMlDsaParametersTest, CreateWithInvalidAlgorithmFails) {
  EXPECT_THAT(JwtMlDsaParameters::Create(
                  JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
                  JwtMlDsaParameters::Algorithm::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("unknown algorithm")));
}

TEST(JwtMlDsaParametersTest, CopyConstructor) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa87);
  ASSERT_THAT(parameters, IsOk());

  JwtMlDsaParameters copy(*parameters);

  EXPECT_THAT(copy, Eq(*parameters));
}

TEST(JwtMlDsaParametersTest, CopyAssignment) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaParameters> copy =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kIgnored,
                                 JwtMlDsaParameters::Algorithm::kMlDsa87);
  ASSERT_THAT(copy, IsOk());

  *copy = *parameters;

  EXPECT_THAT(*copy, Eq(*parameters));
}

TEST(JwtMlDsaParametersTest, MoveConstructor) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa87);
  ASSERT_THAT(parameters, IsOk());

  JwtMlDsaParameters expected(*parameters);
  JwtMlDsaParameters moved(std::move(*parameters));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(JwtMlDsaParametersTest, MoveAssignment) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaParameters> moved =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kIgnored,
                                 JwtMlDsaParameters::Algorithm::kMlDsa87);
  ASSERT_THAT(moved, IsOk());

  JwtMlDsaParameters expected(*parameters);
  *moved = std::move(*parameters);

  EXPECT_THAT(*moved, Eq(expected));
}

TEST_P(JwtMlDsaParametersTest, ParametersEquals) {
  KidStrategyTuple tuple;
  JwtMlDsaParameters::Algorithm algorithm;
  std::tie(tuple, algorithm) = GetParam();

  absl::StatusOr<JwtMlDsaParameters> parameters =
      JwtMlDsaParameters::Create(tuple.kid_strategy, algorithm);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaParameters> other_parameters =
      JwtMlDsaParameters::Create(tuple.kid_strategy, algorithm);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(JwtMlDsaParametersTest, KidStrategyNotEqual) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa87);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaParameters> other_parameters =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kCustom,
                                 JwtMlDsaParameters::Algorithm::kMlDsa87);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(JwtMlDsaParametersTest, AlgorithmNotEqual) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaParameters> other_parameters =
      JwtMlDsaParameters::Create(
          JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
          JwtMlDsaParameters::Algorithm::kMlDsa87);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(JwtMlDsaParametersTest, Clone) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa87);
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  ASSERT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
