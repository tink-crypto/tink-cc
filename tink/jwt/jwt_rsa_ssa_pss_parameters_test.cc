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

#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"

#include <cstdint>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#else
#include "openssl/bn.h"
#endif
#include "tink/big_integer.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/parameters.h"
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

struct TestCase {
  JwtRsaSsaPssParameters::Algorithm algorithm;
  JwtRsaSsaPssParameters::KidStrategy kid_strategy;
  int modulus_size_in_bits;
  bool has_id_requirement;
  bool allow_kid_absent;
};

using JwtRsaSsaPssParametersTest = TestWithParam<TestCase>;

std::string PublicExponentToString(int64_t public_exponent) {
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), public_exponent);

  return internal::BignumToString(e.get(), BN_num_bytes(e.get())).value();
}

const BigInteger& kF4 = *(new BigInteger(PublicExponentToString(65537)));

INSTANTIATE_TEST_SUITE_P(
    JwtRsaSsaPssParametersTestSuite, JwtRsaSsaPssParametersTest,
    Values(TestCase{JwtRsaSsaPssParameters::Algorithm::kPs256,
                    JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId,
                    /*modulus_size_in_bits=*/2048,
                    /*has_id_requirement=*/true,
                    /*allowed_kid_absent=*/false},
           TestCase{JwtRsaSsaPssParameters::Algorithm::kPs384,
                    JwtRsaSsaPssParameters::KidStrategy::kCustom,
                    /*modulus_size_in_bits=*/3072,
                    /*has_id_requirement=*/false, /*allowed_kid_absent=*/true},
           TestCase{JwtRsaSsaPssParameters::Algorithm::kPs512,
                    JwtRsaSsaPssParameters::KidStrategy::kIgnored,
                    /*modulus_size_in_bits=*/2048,
                    /*has_id_requirement=*/false,
                    /*allowed_kid_absent=*/true}));

TEST_P(JwtRsaSsaPssParametersTest, BuildWorks) {
  TestCase test_case = GetParam();

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(kF4)
          .SetAlgorithm(test_case.algorithm)
          .SetKidStrategy(test_case.kid_strategy)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetModulusSizeInBits(),
              Eq(test_case.modulus_size_in_bits));
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(kF4));
  EXPECT_THAT(parameters->GetAlgorithm(), Eq(test_case.algorithm));
  EXPECT_THAT(parameters->GetKidStrategy(), Eq(test_case.kid_strategy));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
  EXPECT_THAT(parameters->AllowKidAbsent(), Eq(test_case.allow_kid_absent));
}

TEST(JwtRsaSsaPssParametersTest, BuildWithInvalidKidStrategyFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::
                  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .Build();
  EXPECT_THAT(parameters.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("unknown kid strategy")));
}

TEST(JwtRsaSsaPssParametersTest, BuildWithoutKidStrategyFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Kid strategy is not set")));
}

TEST(JwtRsaSsaPssParametersTest, BuildWithInvalidAlgorithmFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(
              JwtRsaSsaPssParameters::Algorithm::
                  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  EXPECT_THAT(parameters.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("unknown algorithm")));
}

TEST(JwtRsaSsaPssParametersTest, BuildWithoutAlgorithmFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  EXPECT_THAT(parameters.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("Algorithm is not set")));
}

TEST(JwtRsaSsaPssParametersTest, BuildWithLargeModulusSizeWorks) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(16789)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetModulusSizeInBits(), Eq(16789));
}

TEST(JwtRsaSsaPssParametersTest, BuildWithTooSmallModulusSizeFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2047)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid key size: must be at least 2048 bits")));
}

TEST(JwtRsaSsaPssParametersTest, BuildWithoutModulusSizeFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  EXPECT_THAT(parameters.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("Key size is not set")));
}

TEST(JwtRsaSsaPssParametersTest, BuildWithValidNonF4PublicExponentWorks) {
  BigInteger nonF4_public_exponent =
      BigInteger(PublicExponentToString(1234567));
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(nonF4_public_exponent)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(nonF4_public_exponent));
}

TEST(JwtRsaSsaPssParametersTest, BuildWithoutPublicExponentDefaultsToF4) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(kF4));
}

TEST(JwtRsaSsaPssParametersTest, BuildWithLargePublicExponentWorks) {
  BigInteger large_public_exponent =
      BigInteger(PublicExponentToString(100000001L));
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(large_public_exponent)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(large_public_exponent));
}

TEST(JwtRsaSsaPssParametersTest, BuildWithEvenPublicExponentFails) {
  BigInteger even_public_exponent = BigInteger(PublicExponentToString(123456));
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(even_public_exponent)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Public exponent must be odd")));
}

TEST(JwtRsaSsaPssParametersTest, BuildWithTooSmallPublicExponentFails) {
  BigInteger small_public_exponent = BigInteger(PublicExponentToString(3));
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(small_public_exponent)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Public exponent must be greater than 65536")));
}

TEST(JwtRsaSsaPssParametersTest, BuildWithTooLargePublicExponentFails) {
  // Public exponent must have less than 32 bits.
  BigInteger too_large_public_exponent =
      BigInteger(PublicExponentToString(4294967297L));
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(too_large_public_exponent)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Exponent size must be smaller than 32 bits")));
}

TEST(JwtRsaSsaPssParametersTest, CopyConstructor) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs512)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  JwtRsaSsaPssParameters copy(*parameters);

  EXPECT_THAT(copy.GetKidStrategy(),
              Eq(JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
  EXPECT_THAT(parameters->GetModulusSizeInBits(), Eq(2048));
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(kF4));
  EXPECT_THAT(parameters->GetAlgorithm(),
              Eq(JwtRsaSsaPssParameters::Algorithm::kPs512));
}

TEST(JwtRsaSsaPssParametersTest, CopyAssignment) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs512)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  JwtRsaSsaPssParameters copy = *parameters;

  EXPECT_THAT(copy.GetKidStrategy(),
              Eq(JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
  EXPECT_THAT(parameters->GetModulusSizeInBits(), Eq(2048));
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(kF4));
  EXPECT_THAT(parameters->GetAlgorithm(),
              Eq(JwtRsaSsaPssParameters::Algorithm::kPs512));
}

TEST_P(JwtRsaSsaPssParametersTest, ParametersEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(kF4)
          .SetAlgorithm(test_case.algorithm)
          .SetKidStrategy(test_case.kid_strategy)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPssParameters> other_parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(kF4)
          .SetAlgorithm(test_case.algorithm)
          .SetKidStrategy(test_case.kid_strategy)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(JwtRsaSsaPssParametersTest, KidStrategyNotEqual) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs512)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPssParameters> other_parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs512)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kCustom)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(JwtRsaSsaPssParametersTest, AlgorithmNotEqual) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPssParameters> other_parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs384)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(JwtRsaSsaPssParametersTest, ModulusSizeNotEqual) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPssParameters> other_parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(JwtRsaSsaPssParametersTest, PublicExponentNotEqual) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger nonF4_public_exponent =
      BigInteger(PublicExponentToString(1234567));
  absl::StatusOr<JwtRsaSsaPssParameters> other_parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(nonF4_public_exponent)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(JwtRsaSsaPssParametersTest, Clone) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  ASSERT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
