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

#include "tink/aead/legacy_kms_envelope_aead_parameters.h"

#include <memory>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
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
using ::testing::IsTrue;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kKeyUri = "some://arbitrary.key.uri?q=123#xyz";

struct TestCase {
  LegacyKmsEnvelopeAeadParameters::Variant variant;
  bool has_id_requirement;
};

using LegacyKmsEnvelopeAeadParametersTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    LegacyKmsEnvelopeAeadParametersTests, LegacyKmsEnvelopeAeadParametersTest,
    Values(TestCase{LegacyKmsEnvelopeAeadParameters::Variant::kTink,
                    /*has_id_requirement=*/true},
           TestCase{LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix,
                    /*has_id_requirement=*/false}));

XChaCha20Poly1305Parameters CreateXChaCha20Poly1305KeyParameters() {
  absl::StatusOr<XChaCha20Poly1305Parameters> parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  CHECK_OK(parameters);
  return *parameters;
}

AesGcmParameters CreateAesGcmKeyParameters() {
  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters);
  return *parameters;
}

AesGcmSivParameters CreateAesGcmSivKeyParameters() {
  absl::StatusOr<AesGcmSivParameters> parameters =
      AesGcmSivParameters::Create(16, AesGcmSivParameters::Variant::kNoPrefix);
  CHECK_OK(parameters);
  return *parameters;
}

AesEaxParameters CreateAesEaxKeyParameters() {
  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters);
  return *parameters;
}

AesCtrHmacAeadParameters CreateAesCtrHmacAeadKeyParameters() {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters);
  return *parameters;
}

TEST_P(LegacyKmsEnvelopeAeadParametersTest, Create) {
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

  EXPECT_THAT(parameters->GetKeyUri(), Eq(kKeyUri));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
  EXPECT_THAT(parameters->GetDekParsingStrategy(),
              Eq(LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
                     kAssumeXChaCha20Poly1305));
  EXPECT_THAT(parameters->GetDekParameters(), Eq(dek_parameters));
}

TEST(LegacyKmsEnvelopeAeadParametersTest, CreateWithInvalidVariantFails) {
  XChaCha20Poly1305Parameters dek_parameters =
      CreateXChaCha20Poly1305KeyParameters();

  EXPECT_THAT(LegacyKmsEnvelopeAeadParameters::Create(
                  kKeyUri,
                  LegacyKmsEnvelopeAeadParameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements,
                  LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
                      kAssumeXChaCha20Poly1305,
                  dek_parameters)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(LegacyKmsEnvelopeAeadParametersTest,
     CreateWithDekParametersWithIdRequirementFails) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dek_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(dek_parameters, IsOk());

  EXPECT_THAT(
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          *dek_parameters)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("DEK parameters must not have an ID requirement")));
}

TEST(LegacyKmsEnvelopeAeadParametersTest,
     CreateWithXChaChaDekParametersMismatchingParsingStrategyFails) {
  XChaCha20Poly1305Parameters dek_parameters =
      CreateXChaCha20Poly1305KeyParameters();

  EXPECT_THAT(
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesGcm,
          dek_parameters)
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("mismatching parsing strategy and DEK parameters type")));
}

TEST(LegacyKmsEnvelopeAeadParametersTest,
     CreateWithAesGcmDekParametersMismatchingParsingStrategyFails) {
  AesGcmParameters dek_parameters = CreateAesGcmKeyParameters();

  EXPECT_THAT(
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters)
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("mismatching parsing strategy and DEK parameters type")));
}

TEST(LegacyKmsEnvelopeAeadParametersTest,
     CreateWithAesGcmSivDekParametersMismatchingParsingStrategyFails) {
  AesGcmSivParameters dek_parameters = CreateAesGcmSivKeyParameters();

  EXPECT_THAT(
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesGcm,
          dek_parameters)
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("mismatching parsing strategy and DEK parameters type")));
}

TEST(LegacyKmsEnvelopeAeadParametersTest,
     CreateWithAesEaxDekParametersMismatchingParsingStrategyFails) {
  AesEaxParameters dek_parameters = CreateAesEaxKeyParameters();

  EXPECT_THAT(
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters)
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("mismatching parsing strategy and DEK parameters type")));
}

TEST(LegacyKmsEnvelopeAeadParametersTest,
     CreateWithAesCtrHmacDekParametersMismatchingParsingStrategyFails) {
  AesCtrHmacAeadParameters dek_parameters = CreateAesCtrHmacAeadKeyParameters();

  EXPECT_THAT(
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesEax,
          dek_parameters)
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("mismatching parsing strategy and DEK parameters type")));
}

TEST(LegacyKmsEnvelopeAeadParametersTest, CopyConstructor) {
  AesGcmParameters dek_parameters = CreateAesGcmKeyParameters();

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesGcm,
          dek_parameters);
  ASSERT_THAT(parameters, IsOk());

  LegacyKmsEnvelopeAeadParameters copy(*parameters);

  EXPECT_THAT(copy.GetKeyUri(), Eq(kKeyUri));
  EXPECT_THAT(copy.GetVariant(),
              Eq(LegacyKmsEnvelopeAeadParameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
  EXPECT_THAT(
      copy.GetDekParsingStrategy(),
      Eq(LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesGcm));
  EXPECT_THAT(copy.GetDekParameters(), Eq(dek_parameters));
}

TEST(LegacyKmsEnvelopeAeadParametersTest, CopyAssignment) {
  AesGcmSivParameters dek_parameters = CreateAesGcmSivKeyParameters();
  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesGcmSiv,
          dek_parameters);
  ASSERT_THAT(parameters, IsOk());

  AesGcmParameters copy_dek_parameters = CreateAesGcmKeyParameters();
  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> copy =
      LegacyKmsEnvelopeAeadParameters::Create(
          "some.other.key.uri",
          LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesGcm,
          copy_dek_parameters);
  ASSERT_THAT(copy, IsOk());

  *copy = *parameters;

  EXPECT_THAT(copy->GetKeyUri(), Eq(kKeyUri));
  EXPECT_THAT(copy->GetVariant(),
              Eq(LegacyKmsEnvelopeAeadParameters::Variant::kTink));
  EXPECT_THAT(copy->HasIdRequirement(), IsTrue());
  EXPECT_THAT(copy->GetDekParsingStrategy(),
              Eq(LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
                     kAssumeAesGcmSiv));
  EXPECT_THAT(copy->GetDekParameters(), Eq(dek_parameters));
}

TEST(LegacyKmsEnvelopeAeadParametersTest, MoveConstructor) {
  AesEaxParameters dek_parameters = CreateAesEaxKeyParameters();

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesEax,
          dek_parameters);
  ASSERT_THAT(parameters, IsOk());

  LegacyKmsEnvelopeAeadParameters move(std::move(*parameters));

  EXPECT_THAT(move.GetKeyUri(), Eq(kKeyUri));
  EXPECT_THAT(move.GetVariant(),
              Eq(LegacyKmsEnvelopeAeadParameters::Variant::kTink));
  EXPECT_THAT(move.HasIdRequirement(), IsTrue());
  EXPECT_THAT(
      move.GetDekParsingStrategy(),
      Eq(LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesEax));
  EXPECT_THAT(move.GetDekParameters(), Eq(dek_parameters));
}

TEST(LegacyKmsEnvelopeAeadParametersTest, MoveAssignment) {
  AesCtrHmacAeadParameters dek_parameters = CreateAesCtrHmacAeadKeyParameters();
  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeAesCtrHmac,
          dek_parameters);
  ASSERT_THAT(parameters, IsOk());

  AesEaxParameters move_dek_parameters = CreateAesEaxKeyParameters();
  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> move =
      LegacyKmsEnvelopeAeadParameters::Create(
          "some.other.key.uri",
          LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesEax,
          move_dek_parameters);
  ASSERT_THAT(move, IsOk());

  *move = std::move(*parameters);

  EXPECT_THAT(move->GetKeyUri(), Eq(kKeyUri));
  EXPECT_THAT(move->GetVariant(),
              Eq(LegacyKmsEnvelopeAeadParameters::Variant::kTink));
  EXPECT_THAT(move->HasIdRequirement(), IsTrue());
  EXPECT_THAT(move->GetDekParsingStrategy(),
              Eq(LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
                     kAssumeAesCtrHmac));
  EXPECT_THAT(move->GetDekParameters(), Eq(dek_parameters));
}

TEST_P(LegacyKmsEnvelopeAeadParametersTest, ParametersEquals) {
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

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> other_parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, test_case.variant,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(LegacyKmsEnvelopeAeadParametersTest, DifferentKeyUriNotEqual) {
  XChaCha20Poly1305Parameters dek_parameters =
      CreateXChaCha20Poly1305KeyParameters();

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> other_parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          "some.other.key.uri", LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(LegacyKmsEnvelopeAeadParametersTest, DifferentVariantNotEqual) {
  XChaCha20Poly1305Parameters dek_parameters =
      CreateXChaCha20Poly1305KeyParameters();

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> other_parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(LegacyKmsEnvelopeAeadParametersTest, Clone) {
  XChaCha20Poly1305Parameters dek_parameters =
      CreateXChaCha20Poly1305KeyParameters();
  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(
          kKeyUri, LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305,
          dek_parameters);
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  EXPECT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
