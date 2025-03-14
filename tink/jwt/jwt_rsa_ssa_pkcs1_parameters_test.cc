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

#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"

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
  JwtRsaSsaPkcs1Parameters::Algorithm algorithm;
  JwtRsaSsaPkcs1Parameters::KidStrategy kid_strategy;
  int modulus_size_in_bits;
  bool has_id_requirement;
  bool allow_kid_absent;
};

using JwtRsaSsaPkcs1ParametersTest = TestWithParam<TestCase>;

std::string PublicExponentToString(int64_t public_exponent) {
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), public_exponent);

  return internal::BignumToString(e.get(), BN_num_bytes(e.get())).value();
}

const BigInteger& kF4 = *(new BigInteger(PublicExponentToString(65537)));

INSTANTIATE_TEST_SUITE_P(
    JwtRsaSsaPkcs1ParametersTestSuite, JwtRsaSsaPkcs1ParametersTest,
    Values(TestCase{JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
                    JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId,
                    /*modulus_size_in_bits=*/2048,
                    /*has_id_requirement=*/true,
                    /*allowed_kid_absent=*/false},
           TestCase{JwtRsaSsaPkcs1Parameters::Algorithm::kRs384,
                    JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom,
                    /*modulus_size_in_bits=*/3072,
                    /*has_id_requirement=*/false, /*allowed_kid_absent=*/true},
           TestCase{JwtRsaSsaPkcs1Parameters::Algorithm::kRs512,
                    JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
                    /*modulus_size_in_bits=*/2048,
                    /*has_id_requirement=*/false,
                    /*allowed_kid_absent=*/true}));

TEST_P(JwtRsaSsaPkcs1ParametersTest, BuildWorks) {
  TestCase test_case = GetParam();

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
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

TEST(JwtRsaSsaPkcs1ParametersTest, BuildWithInvalidKidStrategyFails) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::
                  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .Build();
  EXPECT_THAT(parameters.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("unknown kid strategy")));
}

TEST(JwtRsaSsaPkcs1ParametersTest, BuildWithoutKidStrategyFails) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Kid strategy is not set")));
}

TEST(JwtRsaSsaPkcs1ParametersTest, BuildWithInvalidAlgorithmFails) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(
              JwtRsaSsaPkcs1Parameters::Algorithm::
                  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .Build();
  EXPECT_THAT(parameters.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("unknown algorithm")));
}

TEST(JwtRsaSsaPkcs1ParametersTest, BuildWithoutAlgorithmFails) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .Build();
  EXPECT_THAT(parameters.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("Algorithm is not set")));
}

TEST(JwtRsaSsaPkcs1ParametersTest, BuildWithLargeModulusSizeWorks) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(16789)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetModulusSizeInBits(), Eq(16789));
}

TEST(JwtRsaSsaPkcs1ParametersTest, BuildWithTooSmallModulusSizeFails) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2047)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .Build();
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid key size: must be at least 2048 bits")));
}

TEST(JwtRsaSsaPkcs1ParametersTest, BuildWithoutModulusSizeFails) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .Build();
  EXPECT_THAT(parameters.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("Key size is not set")));
}

TEST(JwtRsaSsaPkcs1ParametersTest, BuildWithValidNonF4PublicExponentWorks) {
  BigInteger nonF4_public_exponent =
      BigInteger(PublicExponentToString(1234567));
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(nonF4_public_exponent)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(nonF4_public_exponent));
}

TEST(JwtRsaSsaPkcs1ParametersTest, BuildWithoutPublicExponentDefaultsToF4) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(kF4));
}

TEST(JwtRsaSsaPkcs1ParametersTest, BuildWithLargePublicExponentWorks) {
  BigInteger large_public_exponent =
      BigInteger(PublicExponentToString(100000001L));
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(large_public_exponent)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(large_public_exponent));
}

TEST(JwtRsaSsaPkcs1ParametersTest, BuildWithEvenPublicExponentFails) {
  BigInteger even_public_exponent = BigInteger(PublicExponentToString(123456));
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(even_public_exponent)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Public exponent must be odd")));
}

TEST(JwtRsaSsaPkcs1ParametersTest, BuildWithTooSmallPublicExponentFails) {
  BigInteger small_public_exponent = BigInteger(PublicExponentToString(3));
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(small_public_exponent)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .Build();
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Public exponent must be greater than 65536")));
}

TEST(JwtRsaSsaPkcs1ParametersTest, BuildWithTooLargePublicExponentFails) {
  // Public exponent must have less than 32 bits.
  BigInteger too_large_public_exponent =
      BigInteger(PublicExponentToString(4294967297L));
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(too_large_public_exponent)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .Build();
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Exponent size must be smaller than 32 bits")));
}

TEST(JwtRsaSsaPkcs1ParametersTest, CopyConstructor) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs512)
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  JwtRsaSsaPkcs1Parameters copy(*parameters);

  EXPECT_THAT(copy.GetKidStrategy(),
              Eq(JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
  EXPECT_THAT(parameters->GetModulusSizeInBits(), Eq(2048));
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(kF4));
  EXPECT_THAT(parameters->GetAlgorithm(),
              Eq(JwtRsaSsaPkcs1Parameters::Algorithm::kRs512));
}

TEST(JwtRsaSsaPkcs1ParametersTest, CopyAssignment) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs512)
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  JwtRsaSsaPkcs1Parameters copy = *parameters;

  EXPECT_THAT(copy.GetKidStrategy(),
              Eq(JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
  EXPECT_THAT(parameters->GetModulusSizeInBits(), Eq(2048));
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(kF4));
  EXPECT_THAT(parameters->GetAlgorithm(),
              Eq(JwtRsaSsaPkcs1Parameters::Algorithm::kRs512));
}

TEST_P(JwtRsaSsaPkcs1ParametersTest, ParametersEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(kF4)
          .SetAlgorithm(test_case.algorithm)
          .SetKidStrategy(test_case.kid_strategy)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> other_parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
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

TEST(JwtRsaSsaPkcs1ParametersTest, KidStrategyNotEqual) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs512)
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> other_parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs512)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(JwtRsaSsaPkcs1ParametersTest, AlgorithmNotEqual) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> other_parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs384)
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(JwtRsaSsaPkcs1ParametersTest, ModulusSizeNotEqual) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> other_parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(JwtRsaSsaPkcs1ParametersTest, PublicExponentNotEqual) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger nonF4_public_exponent =
      BigInteger(PublicExponentToString(1234567));
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> other_parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(nonF4_public_exponent)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(JwtRsaSsaPkcs1ParametersTest, Clone) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  ASSERT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
