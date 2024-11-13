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

#include "tink/aead/legacy_kms_aead_key.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/legacy_kms_aead_parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kKeyUri = "some://arbitrary.key.uri?q=123#xyz";

struct TestCase {
  LegacyKmsAeadParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using LegacyKmsAeadKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    LegacyKmsAeadKeyTestSuite, LegacyKmsAeadKeyTest,
    Values(TestCase{LegacyKmsAeadParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{LegacyKmsAeadParameters::Variant::kNoPrefix, absl::nullopt,
                    ""}));

TEST_P(LegacyKmsAeadKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<LegacyKmsAeadKey> key =
      LegacyKmsAeadKey::Create(*parameters, test_case.id_requirement);
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetOutputPrefix(), Eq(test_case.output_prefix));
}

TEST(LegacyKmsAeadKeyTest, CreateKeyWithInvalidIdRequirementFails) {
  util::StatusOr<LegacyKmsAeadParameters> no_prefix_parameters =
      LegacyKmsAeadParameters::Create(
          kKeyUri, LegacyKmsAeadParameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_parameters, IsOk());

  EXPECT_THAT(LegacyKmsAeadKey::Create(*no_prefix_parameters,
                                       /*id_requirement=*/123)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement")));

  util::StatusOr<LegacyKmsAeadParameters> tink_parameters =
      LegacyKmsAeadParameters::Create(kKeyUri,
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(tink_parameters, IsOk());

  EXPECT_THAT(LegacyKmsAeadKey::Create(*tink_parameters,
                                       /*id_requirement=*/absl::nullopt)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key without ID requirement")));
}

TEST_P(LegacyKmsAeadKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<LegacyKmsAeadKey> key =
      LegacyKmsAeadKey::Create(*parameters, test_case.id_requirement);
  ASSERT_THAT(key, IsOk());

  util::StatusOr<LegacyKmsAeadKey> other_key =
      LegacyKmsAeadKey::Create(*parameters, test_case.id_requirement);
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(LegacyKmsAeadKeyTest, DifferentParametersNotEqual) {
  util::StatusOr<LegacyKmsAeadParameters> parameters1 =
      LegacyKmsAeadParameters::Create(
          "key_uri1", LegacyKmsAeadParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters1, IsOk());

  util::StatusOr<LegacyKmsAeadKey> key =
      LegacyKmsAeadKey::Create(*parameters1, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());

  util::StatusOr<LegacyKmsAeadParameters> parameters2 =
      LegacyKmsAeadParameters::Create(
          "key_uri2", LegacyKmsAeadParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters2, IsOk());

  util::StatusOr<LegacyKmsAeadKey> other_key =
      LegacyKmsAeadKey::Create(*parameters2, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(LegacyKmsAeadKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri,
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<LegacyKmsAeadKey> key =
      LegacyKmsAeadKey::Create(*parameters,
                               /*id_requirement=*/0x01020304);
  ASSERT_THAT(key, IsOk());

  util::StatusOr<LegacyKmsAeadKey> other_key =
      LegacyKmsAeadKey::Create(*parameters,
                               /*id_requirement=*/0x02030405);
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(LegacyKmsAeadKeyTest, CopyConstructor) {
  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri,
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<LegacyKmsAeadKey> key =
      LegacyKmsAeadKey::Create(*parameters, /*id_requirement=*/0x123);
  ASSERT_THAT(key, IsOk());

  LegacyKmsAeadKey copy(*key);

  EXPECT_THAT(copy.GetParameters(), Eq(*parameters));
  EXPECT_THAT(copy.GetIdRequirement(), Eq(0x123));
}

TEST(LegacyKmsAeadKeyTest, CopyAssignment) {
  util::StatusOr<LegacyKmsAeadParameters> tink_parameters =
      LegacyKmsAeadParameters::Create(kKeyUri,
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(tink_parameters, IsOk());

  util::StatusOr<LegacyKmsAeadKey> key =
      LegacyKmsAeadKey::Create(*tink_parameters, /*id_requirement=*/0x123);
  ASSERT_THAT(key, IsOk());

  util::StatusOr<LegacyKmsAeadParameters> no_prefix_parameters =
      LegacyKmsAeadParameters::Create(
          kKeyUri, LegacyKmsAeadParameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_parameters, IsOk());

  util::StatusOr<LegacyKmsAeadKey> copy = LegacyKmsAeadKey::Create(
      *no_prefix_parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(copy, IsOk());

  *copy = *key;

  EXPECT_THAT(copy->GetParameters(), Eq(*tink_parameters));
  EXPECT_THAT(copy->GetIdRequirement(), Eq(0x123));
}

TEST(LegacyKmsAeadKeyTest, MoveConstructor) {
  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri,
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<LegacyKmsAeadKey> key =
      LegacyKmsAeadKey::Create(*parameters, /*id_requirement=*/0x123);
  ASSERT_THAT(key, IsOk());

  LegacyKmsAeadKey move = std::move(*key);

  EXPECT_THAT(move.GetParameters(), Eq(*parameters));
  EXPECT_THAT(move.GetIdRequirement(), Eq(0x123));
}

TEST(LegacyKmsAeadKeyTest, MoveAssignment) {
  util::StatusOr<LegacyKmsAeadParameters> tink_parameters =
      LegacyKmsAeadParameters::Create(kKeyUri,
                                      LegacyKmsAeadParameters::Variant::kTink);
  ASSERT_THAT(tink_parameters, IsOk());

  util::StatusOr<LegacyKmsAeadKey> key =
      LegacyKmsAeadKey::Create(*tink_parameters, /*id_requirement=*/0x123);
  ASSERT_THAT(key, IsOk());

  util::StatusOr<LegacyKmsAeadParameters> no_prefix_parameters =
      LegacyKmsAeadParameters::Create(
          kKeyUri, LegacyKmsAeadParameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_parameters, IsOk());

  util::StatusOr<LegacyKmsAeadKey> move = LegacyKmsAeadKey::Create(
      *no_prefix_parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(move, IsOk());

  *move = std::move(*key);

  EXPECT_THAT(move->GetParameters(), Eq(*tink_parameters));
  EXPECT_THAT(move->GetIdRequirement(), Eq(0x123));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
