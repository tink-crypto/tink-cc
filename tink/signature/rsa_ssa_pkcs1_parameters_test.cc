// Copyright 2023 Google LLC
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

#include "tink/signature/rsa_ssa_pkcs1_parameters.h"

#include <cstdint>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#else
#include "openssl/bn.h"
#endif
#include "tink/big_integer.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
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

struct TestCase {
  int modulus_size_in_bits;
  RsaSsaPkcs1Parameters::HashType hash_type;
  RsaSsaPkcs1Parameters::Variant variant;
  bool has_id_requirement;
};

using RsaSsaPkcs1ParametersTest = TestWithParam<TestCase>;

std::string PublicExponentToString(int64_t public_exponent) {
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), public_exponent);

  return internal::BignumToString(e.get(), BN_num_bytes(e.get())).value();
}

const BigInteger& kF4 = *(new BigInteger(PublicExponentToString(65537)));

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPkcs1ParametersTestSuite, RsaSsaPkcs1ParametersTest,
    Values(TestCase{/*modulus_size=*/2048,
                    RsaSsaPkcs1Parameters::HashType::kSha256,
                    RsaSsaPkcs1Parameters::Variant::kTink,
                    /*has_id_requirement=*/true},
           TestCase{/*modulus_size=*/3072,
                    RsaSsaPkcs1Parameters::HashType::kSha256,
                    RsaSsaPkcs1Parameters::Variant::kCrunchy,
                    /*has_id_requirement=*/true},
           TestCase{/*modulus_size=*/2048,
                    RsaSsaPkcs1Parameters::HashType::kSha256,
                    RsaSsaPkcs1Parameters::Variant::kLegacy,
                    /*has_id_requirement=*/true},
           TestCase{/*modulus_size=*/3072,
                    RsaSsaPkcs1Parameters::HashType::kSha256,
                    RsaSsaPkcs1Parameters::Variant::kNoPrefix,
                    /*has_id_requirement=*/false}));

TEST_P(RsaSsaPkcs1ParametersTest, Build) {
  TestCase test_case = GetParam();

  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(kF4)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetModulusSizeInBits(),
              Eq(test_case.modulus_size_in_bits));
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(kF4));
  EXPECT_THAT(parameters->GetHashType(), Eq(test_case.hash_type));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(RsaSsaPkcs1ParametersTest, BuildWithInvalidVariantFails) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::
                          kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1ParametersTest, BuildWithoutVariantFails) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1ParametersTest, BuildWithInvalidHashTypeFails) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(
              RsaSsaPkcs1Parameters::HashType::
                  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1ParametersTest, BuildWithoutHashTypeFails) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1ParametersTest, BuildWithLargeModulusSize) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(16789)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetModulusSizeInBits(), Eq(16789));
}

TEST(RsaSsaPkcs1ParametersTest, BuildWithTooSmallModulusSize) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2047)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1ParametersTest, BuildWithoutModulusSize) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1ParametersTest, BuildWithValidNonF4PublicExponent) {
  BigInteger nonF4_public_exponent =
      BigInteger(PublicExponentToString(1234567));
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(nonF4_public_exponent)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(nonF4_public_exponent));
}

TEST(RsaSsaPkcs1ParametersTest, BuildWithoutPublicExponentDefaultsToF4) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(kF4));
}

TEST(RsaSsaPkcs1ParametersTest, BuildWithSmallPublicExponentFails) {
  BigInteger small_public_exponent = BigInteger(PublicExponentToString(3));
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(small_public_exponent)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1ParametersTest, BuildWithEvenPublicExponentFails) {
  BigInteger even_public_exponent = BigInteger(PublicExponentToString(123456));
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(even_public_exponent)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1ParametersTest, BuildWithLargePublicExponent) {
  BigInteger large_public_exponent =
      BigInteger(PublicExponentToString(100000001L));
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(large_public_exponent)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(large_public_exponent));
}

TEST(RsaSsaPkcs1ParametersTest, BuildWithTooLargePublicExponent) {
  // Public exponent must be smaller than 32 bits.
  BigInteger too_large_public_exponent =
      BigInteger(PublicExponentToString(4294967297L));
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(too_large_public_exponent)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1ParametersTest, CopyConstructor) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RsaSsaPkcs1Parameters copy(*parameters);

  EXPECT_THAT(copy.GetVariant(), Eq(RsaSsaPkcs1Parameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
  EXPECT_THAT(parameters->GetModulusSizeInBits(), Eq(2048));
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(kF4));
  EXPECT_THAT(parameters->GetHashType(),
              Eq(RsaSsaPkcs1Parameters::HashType::kSha512));
}

TEST(RsaSsaPkcs1ParametersTest, CopyAssignment) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RsaSsaPkcs1Parameters copy = *parameters;

  EXPECT_THAT(copy.GetVariant(), Eq(RsaSsaPkcs1Parameters::Variant::kTink));
  EXPECT_THAT(copy.HasIdRequirement(), IsTrue());
  EXPECT_THAT(parameters->GetModulusSizeInBits(), Eq(2048));
  EXPECT_THAT(parameters->GetPublicExponent(), Eq(kF4));
  EXPECT_THAT(parameters->GetHashType(),
              Eq(RsaSsaPkcs1Parameters::HashType::kSha512));
}

TEST_P(RsaSsaPkcs1ParametersTest, ParametersEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(kF4)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1Parameters> other_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(kF4)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(RsaSsaPkcs1ParametersTest, VariantNotEqual) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1Parameters> other_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kCrunchy)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(RsaSsaPkcs1ParametersTest, HashTypeNotEqual) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1Parameters> other_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(RsaSsaPkcs1ParametersTest, ModulusSizeNotEqual) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1Parameters> other_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(RsaSsaPkcs1ParametersTest, PublicExponentNotEqual) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger nonF4_public_exponent =
      BigInteger(PublicExponentToString(1234567));
  absl::StatusOr<RsaSsaPkcs1Parameters> other_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(nonF4_public_exponent)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(RsaSsaPkcs1ParametersTest, Clonel) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  ASSERT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
