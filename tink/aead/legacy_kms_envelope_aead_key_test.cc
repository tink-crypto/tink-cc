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

#include "tink/aead/legacy_kms_envelope_aead_key.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/legacy_kms_envelope_aead_parameters.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/key.h"
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

XChaCha20Poly1305Parameters CreateXChaCha20Poly1305KeyParameters() {
  absl::StatusOr<XChaCha20Poly1305Parameters> parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ABSL_CHECK_OK(parameters);
  return *parameters;
}

struct TestCase {
  LegacyKmsEnvelopeAeadParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using LegacyKmsEnvelopeAeadKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    LegacyKmsEnvelopeAeadKeyTestSuite, LegacyKmsEnvelopeAeadKeyTest,
    Values(TestCase{LegacyKmsEnvelopeAeadParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix,
                    absl::nullopt, ""}));

TEST_P(LegacyKmsEnvelopeAeadKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();
  XChaCha20Poly1305Parameters dek_parameters =
      CreateXChaCha20Poly1305KeyParameters();

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, test_case.variant,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> key =
      LegacyKmsEnvelopeAeadKey::Create(*parameters, test_case.id_requirement);
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetOutputPrefix(), Eq(test_case.output_prefix));
}

TEST(LegacyKmsEnvelopeAeadKeyTest, CreateKeyWithInvalidIdRequirementFails) {
  XChaCha20Poly1305Parameters dek_parameters =
      CreateXChaCha20Poly1305KeyParameters();
  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> no_prefix_parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(no_prefix_parameters, IsOk());

  EXPECT_THAT(LegacyKmsEnvelopeAeadKey::Create(*no_prefix_parameters,
                                               /*id_requirement=*/123)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement")));

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> tink_parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(tink_parameters, IsOk());

  EXPECT_THAT(LegacyKmsEnvelopeAeadKey::Create(*tink_parameters,
                                               /*id_requirement=*/absl::nullopt)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key without ID requirement")));
}

TEST_P(LegacyKmsEnvelopeAeadKeyTest, KeyEquals) {
  TestCase test_case = GetParam();
  XChaCha20Poly1305Parameters dek_parameters =
      CreateXChaCha20Poly1305KeyParameters();

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, test_case.variant,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> key =
      LegacyKmsEnvelopeAeadKey::Create(*parameters, test_case.id_requirement);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> other_key =
      LegacyKmsEnvelopeAeadKey::Create(*parameters, test_case.id_requirement);
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(LegacyKmsEnvelopeAeadKeyTest, DifferentParametersNotEqual) {
  XChaCha20Poly1305Parameters dek_parameters =
      CreateXChaCha20Poly1305KeyParameters();

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters1 =
      LegacyKmsEnvelopeAeadParameters::Create(
          "key_uri1", LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(parameters1, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> key =
      LegacyKmsEnvelopeAeadKey::Create(*parameters1,
                                       /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters2 =
      LegacyKmsEnvelopeAeadParameters::Create(
          "key_uri2", LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(parameters2, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> other_key =
      LegacyKmsEnvelopeAeadKey::Create(*parameters2,
                                       /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(LegacyKmsEnvelopeAeadKeyTest, DifferentIdRequirementNotEqual) {
  XChaCha20Poly1305Parameters dek_parameters =
      CreateXChaCha20Poly1305KeyParameters();

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> key =
      LegacyKmsEnvelopeAeadKey::Create(*parameters,
                                       /*id_requirement=*/0x01020304);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> other_key =
      LegacyKmsEnvelopeAeadKey::Create(*parameters,
                                       /*id_requirement=*/0x02030405);
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(LegacyKmsEnvelopeAeadKeyTest, CopyConstructor) {
  XChaCha20Poly1305Parameters dek_parameters =
      CreateXChaCha20Poly1305KeyParameters();

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> key =
      LegacyKmsEnvelopeAeadKey::Create(*parameters, /*id_requirement=*/0x123);
  ASSERT_THAT(key, IsOk());

  LegacyKmsEnvelopeAeadKey copy(*key);

  EXPECT_THAT(copy.GetParameters(), Eq(*parameters));
  EXPECT_THAT(copy.GetIdRequirement(), Eq(0x123));
}

TEST(LegacyKmsEnvelopeAeadKeyTest, CopyAssignment) {
  XChaCha20Poly1305Parameters dek_parameters =
      CreateXChaCha20Poly1305KeyParameters();

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> tink_parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(tink_parameters, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> key =
      LegacyKmsEnvelopeAeadKey::Create(*tink_parameters,
                                       /*id_requirement=*/0x123);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> no_prefix_parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(no_prefix_parameters, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> copy =
      LegacyKmsEnvelopeAeadKey::Create(*no_prefix_parameters,
                                       /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(copy, IsOk());

  *copy = *key;

  EXPECT_THAT(copy->GetParameters(), Eq(*tink_parameters));
  EXPECT_THAT(copy->GetIdRequirement(), Eq(0x123));
}

TEST(LegacyKmsEnvelopeAeadKeyTest, MoveConstructor) {
  XChaCha20Poly1305Parameters dek_parameters =
      CreateXChaCha20Poly1305KeyParameters();

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> key =
      LegacyKmsEnvelopeAeadKey::Create(*parameters, /*id_requirement=*/0x123);
  ASSERT_THAT(key, IsOk());

  LegacyKmsEnvelopeAeadKey move = std::move(*key);

  EXPECT_THAT(move.GetParameters(), Eq(*parameters));
  EXPECT_THAT(move.GetIdRequirement(), Eq(0x123));
}

TEST(LegacyKmsEnvelopeAeadKeyTest, MoveAssignment) {
  XChaCha20Poly1305Parameters dek_parameters =
      CreateXChaCha20Poly1305KeyParameters();

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> tink_parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(tink_parameters, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> key =
      LegacyKmsEnvelopeAeadKey::Create(*tink_parameters,
                                       /*id_requirement=*/0x123);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> no_prefix_parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(no_prefix_parameters, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> move =
      LegacyKmsEnvelopeAeadKey::Create(*no_prefix_parameters,
                                       /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(move, IsOk());

  *move = std::move(*key);

  EXPECT_THAT(move->GetParameters(), Eq(*tink_parameters));
  EXPECT_THAT(move->GetIdRequirement(), Eq(0x123));
}

TEST(LegacyKmsEnvelopeAeadKeyTest, Clone) {
  XChaCha20Poly1305Parameters dek_parameters =
      CreateXChaCha20Poly1305KeyParameters();

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> key =
      LegacyKmsEnvelopeAeadKey::Create(*parameters, /*id_requirement=*/0x123);
  ASSERT_THAT(key, IsOk());

  std::unique_ptr<Key> cloned_key = key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
