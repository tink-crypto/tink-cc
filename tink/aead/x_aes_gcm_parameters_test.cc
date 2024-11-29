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

#include "tink/aead/x_aes_gcm_parameters.h"

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
using ::testing::IsTrue;
using ::testing::TestWithParam;
using ::testing::Values;

constexpr int kDefaultSaltSize = 12;

struct TestCase {
  XAesGcmParameters::Variant variant;
  int salt_size;
  bool has_id_requirement;
};

using XAesGcmParametersTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(XAesGcmParametersTestSuite, XAesGcmParametersTest,
                         Values(TestCase{XAesGcmParameters::Variant::kTink,
                                         /*salt_size=*/8,
                                         /*has_id_requirement=*/true},
                                TestCase{XAesGcmParameters::Variant::kTink,
                                         /*salt_size=*/10,
                                         /*has_id_requirement=*/true},
                                TestCase{XAesGcmParameters::Variant::kNoPrefix,
                                         /*salt_size=*/12,
                                         /*has_id_requirement=*/false}));

TEST_P(XAesGcmParametersTest, Create) {
  TestCase test_case = GetParam();

  util::StatusOr<XAesGcmParameters> parameters =
      XAesGcmParameters::Create(test_case.variant, test_case.salt_size);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->SaltSizeBytes(), Eq(test_case.salt_size));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(XAesGcmParametersTest, CreateWithInvalidVariantFails) {
  EXPECT_THAT(XAesGcmParameters::Create(
                  XAesGcmParameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements,
                  kDefaultSaltSize)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(XAesGcmParametersTest, CreateWithInvalidSaltSizeFails) {
  for (const int salt_size : {-1, 7, 13, 14}) {
    EXPECT_THAT(
        XAesGcmParameters::Create(XAesGcmParameters::Variant::kTink, salt_size)
            .status(),
        StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(XAesGcmParametersTest, CopyConstructor) {
  util::StatusOr<XAesGcmParameters> parameters = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kDefaultSaltSize);
  ASSERT_THAT(parameters, IsOk());

  XAesGcmParameters copy(*parameters);

  EXPECT_THAT(copy.SaltSizeBytes(), Eq(kDefaultSaltSize));
  EXPECT_THAT(copy.GetVariant(), Eq(XAesGcmParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST(XAesGcmParametersTest, CopyAssignment) {
  util::StatusOr<XAesGcmParameters> parameters = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kDefaultSaltSize);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<XAesGcmParameters> copy = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kNoPrefix, /*salt_size_bytes=*/10);
  ASSERT_THAT(copy, IsOk());

  *copy = *parameters;

  EXPECT_THAT(copy->SaltSizeBytes(), Eq(kDefaultSaltSize));
  EXPECT_THAT(copy->GetVariant(), Eq(XAesGcmParameters::Variant::kTink));
  EXPECT_THAT(copy->HasIdRequirement(), IsTrue());
}

TEST(XAesGcmParametersTest, MoveConstructor) {
  util::StatusOr<XAesGcmParameters> parameters = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kDefaultSaltSize);
  ASSERT_THAT(parameters, IsOk());

  XAesGcmParameters move(std::move(*parameters));

  EXPECT_THAT(move.SaltSizeBytes(), Eq(kDefaultSaltSize));
  EXPECT_THAT(move.GetVariant(), Eq(XAesGcmParameters::Variant::kTink));
  EXPECT_THAT(move.HasIdRequirement(), IsTrue());
}

TEST(XAesGcmParametersTest, MoveAssignment) {
  util::StatusOr<XAesGcmParameters> parameters = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kDefaultSaltSize);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<XAesGcmParameters> move = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kNoPrefix, /*salt_size_bytes=*/10);
  ASSERT_THAT(move, IsOk());

  *move = std::move(*parameters);

  EXPECT_THAT(move->SaltSizeBytes(), Eq(kDefaultSaltSize));
  EXPECT_THAT(move->GetVariant(), Eq(XAesGcmParameters::Variant::kTink));
  EXPECT_THAT(move->HasIdRequirement(), IsTrue());
}

TEST_P(XAesGcmParametersTest, ParametersEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<XAesGcmParameters> parameters =
      XAesGcmParameters::Create(test_case.variant, test_case.salt_size);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<XAesGcmParameters> other_parameters =
      XAesGcmParameters::Create(test_case.variant, test_case.salt_size);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(XAesGcmParametersTest, DifferentVariantNotEqual) {
  util::StatusOr<XAesGcmParameters> parameters = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kDefaultSaltSize);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<XAesGcmParameters> other_parameters =
      XAesGcmParameters::Create(XAesGcmParameters::Variant::kNoPrefix,
                                kDefaultSaltSize);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(XAesGcmParametersTest, DifferentSaltSizeNotEqual) {
  util::StatusOr<XAesGcmParameters> parameters = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kDefaultSaltSize);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<XAesGcmParameters> other_parameters =
      XAesGcmParameters::Create(XAesGcmParameters::Variant::kTink,
                                /*salt_size_bytes=*/10);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(XAesGcmParametersTest, Clone) {
  util::StatusOr<XAesGcmParameters> parameters = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kDefaultSaltSize);
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  ASSERT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
