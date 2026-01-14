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

#include "tink/prf/hmac_prf_parameters.h"

#include <memory>
#include <utility>

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
using ::testing::HasSubstr;
using ::testing::IsFalse;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  int key_size;
  HmacPrfParameters::HashType hash_type;
};

using HmacPrfParametersTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    HmacPrfParametersCreateTestSuite, HmacPrfParametersTest,
    Values(TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha1},
           TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha224},
           TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha256},
           TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha384},
           TestCase{/*key_size=*/32, HmacPrfParameters::HashType::kSha512}));

TEST_P(HmacPrfParametersTest, Create) {
  TestCase test_case = GetParam();

  absl::StatusOr<HmacPrfParameters> parameters =
      HmacPrfParameters::Create(test_case.key_size, test_case.hash_type);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->KeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(parameters->GetHashType(), Eq(test_case.hash_type));
  EXPECT_THAT(parameters->HasIdRequirement(), IsFalse());
}

TEST(HmacPrfParametersTest, CreateWithInvalidKeySizeFails) {
  EXPECT_THAT(HmacPrfParameters::Create(/*key_size_in_bytes=*/15,
                                        HmacPrfParameters::HashType::kSha256)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Key size must be at least 16 bytes")));
}

TEST(HmacPrfParametersTest, CreateWithInvalidKHashTypeFails) {
  EXPECT_THAT(
      HmacPrfParameters::Create(
          /*key_size_in_bytes=*/16,
          HmacPrfParameters::HashType::
              kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Cannot create HmacPrf parameters with unknown HashType")));
}

TEST(HmacPrfParametersTest, CopyConstructor) {
  absl::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());

  HmacPrfParameters copy(*parameters);

  EXPECT_THAT(copy, Eq(*parameters));
}

TEST(HmacPrfParametersTest, CopyAssignment) {
  absl::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HmacPrfParameters> copy =
      HmacPrfParameters::Create(
          /*key_size_in_bytes=*/32, HmacPrfParameters::HashType::kSha512);
  ASSERT_THAT(copy, IsOk());

  *copy = *parameters;

  EXPECT_THAT(*copy, Eq(*parameters));
}

TEST(HmacPrfParametersTest, MoveConstructor) {
  absl::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());

  HmacPrfParameters expected = *parameters;

  HmacPrfParameters moved(std::move(*parameters));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(HmacPrfParametersTest, MoveAssignment) {
  absl::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HmacPrfParameters> moved =
      HmacPrfParameters::Create(
          /*key_size_in_bytes=*/32, HmacPrfParameters::HashType::kSha512);
  ASSERT_THAT(moved, IsOk());

  HmacPrfParameters expected = *parameters;

  *moved = std::move(*parameters);

  EXPECT_THAT(*moved, Eq(expected));
}

TEST_P(HmacPrfParametersTest, ParametersEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<HmacPrfParameters> parameters =
      HmacPrfParameters::Create(test_case.key_size, test_case.hash_type);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HmacPrfParameters> other_parameters =
      HmacPrfParameters::Create(test_case.key_size, test_case.hash_type);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(HmacPrfParametersTest, DifferentKeySizeNotEqual) {
  absl::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HmacPrfParameters> other_parameters =
      HmacPrfParameters::Create(/*key_size_in_bytes=*/32,
                                HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(HmacPrfParametersTest, DifferentashTypeNotEqual) {
  absl::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HmacPrfParameters> other_parameters =
      HmacPrfParameters::Create(/*key_size_in_bytes=*/16,
                                HmacPrfParameters::HashType::kSha512);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(HmacPrfParametersTest, Clone) {
  absl::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  ASSERT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
