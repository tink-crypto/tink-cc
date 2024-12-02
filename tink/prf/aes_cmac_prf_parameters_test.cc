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

#include "tink/prf/aes_cmac_prf_parameters.h"

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
using ::testing::IsFalse;
using ::testing::TestWithParam;
using ::testing::Values;

using AesCmacPrfParametersTest = TestWithParam<int>;

INSTANTIATE_TEST_SUITE_P(AesCmacPrfParametersTestSuite,
                         AesCmacPrfParametersTest, Values(16, 32));

TEST_P(AesCmacPrfParametersTest, Create) {
  int key_size = GetParam();

  util::StatusOr<AesCmacPrfParameters> parameters =
      AesCmacPrfParameters::Create(key_size);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->KeySizeInBytes(), Eq(key_size));
  EXPECT_THAT(parameters->HasIdRequirement(), IsFalse());
}

TEST(AesCmacPrfParametersTest, CreateWithInvalidKeySizeFails) {
  EXPECT_THAT(AesCmacPrfParameters::Create(/*key_size_in_bytes=*/17).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesCmacPrfParameters::Create(/*key_size_in_bytes=*/33).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCmacPrfParametersTest, CopyConstructor) {
  util::StatusOr<AesCmacPrfParameters> parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/16);
  ASSERT_THAT(parameters, IsOk());

  AesCmacPrfParameters copy(*parameters);

  EXPECT_THAT(copy.KeySizeInBytes(), Eq(16));
  EXPECT_THAT(copy.HasIdRequirement(), IsFalse());
}

TEST(AesCmacPrfParametersTest, CopyAssignment) {
  util::StatusOr<AesCmacPrfParameters> parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/16);
  ASSERT_THAT(parameters, IsOk());

  AesCmacPrfParameters copy = *parameters;

  EXPECT_THAT(copy.KeySizeInBytes(), Eq(16));
  EXPECT_THAT(copy.HasIdRequirement(), IsFalse());
}

TEST_P(AesCmacPrfParametersTest, ParametersEquals) {
  int key_size = GetParam();

  util::StatusOr<AesCmacPrfParameters> parameters =
      AesCmacPrfParameters::Create(key_size);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesCmacPrfParameters> other_parameters =
      AesCmacPrfParameters::Create(key_size);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(AesCmacPrfParametersTest, DifferentKeySizeNotEqual) {
  util::StatusOr<AesCmacPrfParameters> parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/16);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<AesCmacPrfParameters> other_parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/32);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesCmacPrfParametersTest, Clone) {
  util::StatusOr<AesCmacPrfParameters> parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/16);
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  ASSERT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
