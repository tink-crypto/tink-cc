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

#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  JwtRsaSsaPssParameters::Algorithm algorithm;
  JwtRsaSsaPssParameters::KidStrategy kid_strategy;
  absl::optional<int> id_requirement;
  absl::optional<std::string> custom_kid;
  absl::optional<std::string> expected_kid;
};

const BigInteger& kF4 = *new BigInteger(std::string("\x1\0\x1", 3));  // 65537

// Test vector from https://www.rfc-editor.org/rfc/rfc7517#appendix-C.1
constexpr absl::string_view k2048BitRsaModulus =
    "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-"
    "TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_"
    "LYywlAGZ21WSdS_"
    "PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-"
    "AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_"
    "aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q";

std::string Base64WebSafeDecode(absl::string_view base64_string) {
  std::string dest;
  CHECK(absl::WebSafeBase64Unescape(base64_string, &dest))
      << "Failed to base64 decode.";

  return dest;
}

using JwtRsaSsaPssPublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    JwtRsaSsaPssPublicKeyTestSuite, JwtRsaSsaPssPublicKeyTest,
    Values(TestCase{JwtRsaSsaPssParameters::Algorithm::kPs256,
                    JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId,
                    /*id_requirement=*/0x1ac6a944,
                    /*custom_kid=*/absl::nullopt, /*expected_kid=*/"GsapRA"},
           TestCase{JwtRsaSsaPssParameters::Algorithm::kPs384,
                    JwtRsaSsaPssParameters::KidStrategy::kCustom,
                    /*id_requirement=*/absl::nullopt,
                    /*custom_kid=*/"custom_kid", /*expected_kid=*/"custom_kid"},
           TestCase{JwtRsaSsaPssParameters::Algorithm::kPs512,
                    JwtRsaSsaPssParameters::KidStrategy::kIgnored,
                    /*id_requirement=*/absl::nullopt,
                    /*custom_kid=*/absl::nullopt,
                    /*expected_kid=*/absl::nullopt}));

TEST_P(JwtRsaSsaPssPublicKeyTest, BuildWorks) {
  TestCase test_case = GetParam();

  util::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(test_case.algorithm)
          .SetKidStrategy(test_case.kid_strategy)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  JwtRsaSsaPssPublicKey::Builder builder = JwtRsaSsaPssPublicKey::Builder()
                                               .SetParameters(*parameters)
                                               .SetModulus(modulus);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }

  util::StatusOr<JwtRsaSsaPssPublicKey> key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetModulus(GetPartialKeyAccess()), Eq(modulus));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetKid(), Eq(test_case.expected_kid));
}

TEST(JwtRsaSsaPssPublicKeyTest, BuildWithoutModulusFails) {
  util::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .Build(GetPartialKeyAccess());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                     HasSubstr("modulus must be specified")));
}

TEST(JwtRsaSsaPssPublicKeyTest, BuildWithNonMatchingModulusSizeFails) {
  util::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .Build(GetPartialKeyAccess());
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid modulus length (expected 3072, got 2048)")));
}

TEST(JwtEcdsaPublicKeyTest, BuildBase64EncodedKidWithoutIdRequirementFails) {
  util::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .Build(GetPartialKeyAccess());

  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key without ID requirement "
                                 "with parameters with ID requirement")));
}

TEST(JwtEcdsaPublicKeyTest, BuildBase64EncodedKidWithCustomKidFails) {
  util::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .SetIdRequirement(123)
                                                  .SetCustomKid("custom_kid")
                                                  .Build(GetPartialKeyAccess());

  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Custom kid must not be set for "
                                 "KidStrategy::kBase64EncodedKeyId")));
}

TEST(JwtEcdsaPublicKeyTest, BuildCustomKidWithIdRequirementFails) {
  util::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kCustom)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .SetIdRequirement(123)
                                                  .SetCustomKid("custom_kid")
                                                  .Build(GetPartialKeyAccess());

  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement with "
                                 "parameters without ID requirement")));
}

TEST(JwtEcdsaPublicKeyTest, BuildCustomKidWithoutCustomKidFails) {
  util::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kCustom)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .Build(GetPartialKeyAccess());

  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Custom kid must be set for KidStrategy::kCustom")));
}

TEST(JwtEcdsaPublicKeyTest, BuildIgnoredKidWithIdRequirementFails) {
  util::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .SetIdRequirement(123)
                                                  .Build(GetPartialKeyAccess());

  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement with "
                                 "parameters without ID requirement")));
}

TEST(JwtEcdsaPublicKeyTest, BuildIgnoredKidWithCustomKidFails) {
  util::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .SetCustomKid("custom_kid")
                                                  .Build(GetPartialKeyAccess());

  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Custom kid must not be set for KidStrategy::kIgnored")));
}

TEST(JwtEcdsaPublicKeyTest, BuildWithMissingParametersFails) {
  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<JwtRsaSsaPssPublicKey> key =
      JwtRsaSsaPssPublicKey::Builder().SetModulus(modulus).Build(
          GetPartialKeyAccess());

  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("parameters must be specified")));
}

TEST(JwtEcdsaPublicKeyTest, BuildWithMissingModulusFails) {
  util::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .Build(GetPartialKeyAccess());

  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                     HasSubstr("modulus must be specified")));
}

TEST_P(JwtRsaSsaPssPublicKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(test_case.algorithm)
          .SetKidStrategy(test_case.kid_strategy)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  JwtRsaSsaPssPublicKey::Builder builder = JwtRsaSsaPssPublicKey::Builder()
                                               .SetParameters(*parameters)
                                               .SetModulus(modulus);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }

  util::StatusOr<JwtRsaSsaPssPublicKey> key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  JwtRsaSsaPssPublicKey::Builder other_builder =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(modulus);
  if (test_case.id_requirement.has_value()) {
    other_builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    other_builder.SetCustomKid(*test_case.custom_kid);
  }

  util::StatusOr<JwtRsaSsaPssPublicKey> other_key =
      other_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(JwtRsaSsaPssPublicKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .SetIdRequirement(123)
                                                  .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<JwtRsaSsaPssPublicKey> other_key =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(modulus)
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(JwtRsaSsaPssPublicKeyTest, DifferentModulusNotEqual) {
  util::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string other_modulus_bytes = test::HexDecodeOrDie(
      "00dd904590397808c4314329623d9013453843251b13b8b3c4fef54598112af3eb31c711"
      "03c6259951674e53bd93a7e36d19472e474ebe8028686d9529484d8bafea4a04ba195556"
      "67616c8478670594009c9bc6a3efe52274cba64c724747d7edc194e4fedde32a3289d94c"
      "31936e7e7a15d756f548492f5b345b927e8c618bdd550acb21a17ae148304383db9b3c7b"
      "aa3e4c8bd8e844a884daa3e18d56998cb32f9bae4d41d56a18ddd4313c8089b75e9dbb91"
      "28470bac9b087fb61928ab0f8c4c89360b020899008d08e8bd31f907a807e8056ad6800d"
      "ffdf9ed9d964a939e7e48114b84978551acb85c9df9196f3eff55286d6cd4b39a822a8a7"
      "763a18208f");

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  BigInteger other_modulus(other_modulus_bytes);

  util::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<JwtRsaSsaPssPublicKey> other_key =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(other_modulus)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(JwtRsaSsaPssPublicKeyTest, DifferentCustomKidNotEqual) {
  util::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kCustom)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .SetCustomKid("custom_kid")
                                                  .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<JwtRsaSsaPssPublicKey> other_key =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(modulus)
          .SetCustomKid("other_custom_kid")
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
