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

#include "tink/aead/legacy_kms_aead_parameters.h"

#include <memory>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
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

const absl::string_view kKeyUri = "some://arbitrary.key.uri?q=123#xyz";

struct TestCase {
  LegacyKmsAeadParameters::Variant variant;
  bool has_id_requirement;
};

using LegacyKmsAeadParametersTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    LegacyKmsAeadParametersTests, LegacyKmsAeadParametersTest,
    Values(TestCase{LegacyKmsAeadParameters::Variant::kTink,
                    /*has_id_requirement=*/true},
           TestCase{LegacyKmsAeadParameters::Variant::kNoPrefix,
                    /*has_id_requirement=*/false}));

TEST_P(LegacyKmsAeadParametersTest, Create) {
  TestCase test_case = GetParam();

  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetKeyUri(), Eq(kKeyUri));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(LegacyKmsAeadParametersTest, CreateWithInvalidVariantFails) {
  EXPECT_THAT(
      LegacyKmsAeadParameters::Create(
          kKeyUri, LegacyKmsAeadParameters::Variant::
                       kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(LegacyKmsAeadParametersTest, CopyConstructor) {
  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri,
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  LegacyKmsAeadParameters copy(*parameters);

  EXPECT_THAT(copy.GetKeyUri(), Eq(kKeyUri));
  EXPECT_THAT(copy.GetVariant(), Eq(LegacyKmsAeadParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
}

TEST(LegacyKmsAeadParametersTest, CopyAssignment) {
  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri,
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<LegacyKmsAeadParameters> copy =
      LegacyKmsAeadParameters::Create(
          "some.other.key.uri", LegacyKmsAeadParameters::Variant::kNoPrefix);
  ASSERT_THAT(copy, IsOk());

  *copy = *parameters;

  EXPECT_THAT(copy->GetKeyUri(), Eq(kKeyUri));
  EXPECT_THAT(copy->GetVariant(), Eq(LegacyKmsAeadParameters::Variant::kTink));
  EXPECT_THAT(copy->HasIdRequirement(), IsTrue());
}

TEST(LegacyKmsAeadParametersTest, MoveConstructor) {
  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri,
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  LegacyKmsAeadParameters move(std::move(*parameters));

  EXPECT_THAT(move.GetKeyUri(), Eq(kKeyUri));
  EXPECT_THAT(move.GetVariant(), Eq(LegacyKmsAeadParameters::Variant::kTink));
  EXPECT_THAT(move.HasIdRequirement(), IsTrue());
}

TEST(LegacyKmsAeadParametersTest, MoveAssignment) {
  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri,
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<LegacyKmsAeadParameters> move =
      LegacyKmsAeadParameters::Create(
          "some.other.key.uri", LegacyKmsAeadParameters::Variant::kNoPrefix);
  ASSERT_THAT(move, IsOk());

  *move = std::move(*parameters);

  EXPECT_THAT(move->GetKeyUri(), Eq(kKeyUri));
  EXPECT_THAT(move->GetVariant(), Eq(LegacyKmsAeadParameters::Variant::kTink));
  EXPECT_THAT(move->HasIdRequirement(), IsTrue());
}

TEST_P(LegacyKmsAeadParametersTest, ParametersEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<LegacyKmsAeadParameters> other_parameters =
      LegacyKmsAeadParameters::Create(kKeyUri, test_case.variant);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(LegacyKmsAeadParametersTest, DifferentKeyUriNotEqual) {
  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri,
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<LegacyKmsAeadParameters> other_parameters =
      LegacyKmsAeadParameters::Create("some.other.key.uri",
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(LegacyKmsAeadParametersTest, DifferentVariantNotEqual) {
  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri,
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<LegacyKmsAeadParameters> other_parameters =
      LegacyKmsAeadParameters::Create(
          kKeyUri, LegacyKmsAeadParameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(LegacyKmsAeadParametersTest, Clone) {
  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri,
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  ASSERT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
