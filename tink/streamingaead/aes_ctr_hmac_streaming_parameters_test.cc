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

#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"

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
using ::testing::HasSubstr;
using ::testing::IsFalse;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  int key_size;
  int derived_key_size;
  AesCtrHmacStreamingParameters::HashType hkdf_hash_type;
  AesCtrHmacStreamingParameters::HashType hmac_hash_type;
  int tag_size;
  int segment_size;
};

using AesCtrHmacStreamingParametersTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    BuildTestSuite, AesCtrHmacStreamingParametersTest,
    Values(
        TestCase{
            /*key_size=*/19, /*derived_key_size=*/16,
            /*hkdf_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha1,
            /*hmac_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha1,
            /*tag_size=*/10, /*segment_size=*/1024},
        TestCase{
            /*key_size=*/19, /*derived_key_size=*/16,
            /*hkdf_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha256,
            /*hmac_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha1,
            /*tag_size=*/14, /*segment_size=*/1024 * 1024},
        TestCase{
            /*key_size=*/35, /*derived_key_size=*/32,
            /*hkdf_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha512,
            /*hmac_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha256,
            /*tag_size=*/16, /*segment_size=*/3 * 1024 * 1024},
        TestCase{
            /*key_size=*/35, /*derived_key_size=*/32,
            /*hkdf_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha512,
            /*hmac_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha512,
            /*tag_size=*/64, /*segment_size=*/4 * 1024 * 1024}));

TEST_P(AesCtrHmacStreamingParametersTest, Build) {
  TestCase test_case = GetParam();

  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetDerivedKeySizeInBytes(test_case.derived_key_size)
          .SetHkdfHashType(test_case.hkdf_hash_type)
          .SetHmacHashType(test_case.hmac_hash_type)
          .SetHmacTagSizeInBytes(test_case.tag_size)
          .SetCiphertextSegmentSizeInBytes(test_case.segment_size)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->KeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(parameters->DerivedKeySizeInBytes(),
              Eq(test_case.derived_key_size));
  EXPECT_THAT(parameters->HkdfHashType(), Eq(test_case.hkdf_hash_type));
  EXPECT_THAT(parameters->HmacHashType(), Eq(test_case.hmac_hash_type));
  EXPECT_THAT(parameters->HmacTagSizeInBytes(), Eq(test_case.tag_size));
  EXPECT_THAT(parameters->CiphertextSegmentSizeInBytes(),
              Eq(test_case.segment_size));
  EXPECT_THAT(parameters->HasIdRequirement(), IsFalse());
}

TEST(AesCtrHmacStreamingParametersTest, BuildWithoutSettingKeySizeFails) {
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Key size must be set")));
}

TEST(AesCtrHmacStreamingParametersTest, BuildWithInvalidKeySizeFails) {
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(15)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Key size must be at least the derived key size")));
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(31)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Key size must be at least the derived key size")));
}

TEST(AesCtrHmacStreamingParametersTest,
     BuildWithoutSettingDerivedKeySizeFails) {
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Derived key size must be set")));
}

TEST(AesCtrHmacStreamingParametersTest, BuildWithInvalidDerivedKeySizeFails) {
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(17)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Derived key size must be either 16 or 32 bytes")));
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(33)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Derived key size must be either 16 or 32 bytes")));
}

TEST(AesCtrHmacStreamingParametersTest, BuildWithoutSettingHkdfHashTypeFails) {
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("HKDF hash type must be set")));
}

TEST(AesCtrHmacStreamingParametersTest, BuildWithInvalidHkdfHashTypeFails) {
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(
              AesCtrHmacStreamingParameters::HashType::
                  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("HKDF hash type not supported")));
}

TEST(AesCtrHmacStreamingParametersTest, BuildWithoutSettingHmacHashTypeFails) {
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("HMAC hash type must be set")));
}

TEST(AesCtrHmacStreamingParametersTest, BuildWithInvalidHmacHashTypeFails) {
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(
              AesCtrHmacStreamingParameters::HashType::
                  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("HMAC hash type not supported")));
}

TEST(AesCtrHmacStreamingParametersTest, BuildWithoutSettingTagSizeFails) {
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("HMAC tag size must be set")));
}

TEST(AesCtrHmacStreamingParametersTest, BuildWithInvalidTagSizeFails) {
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha1)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha1)
          .SetHmacTagSizeInBytes(9)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Tag size is too small")));
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha1)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha1)
          .SetHmacTagSizeInBytes(21)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Tag size is too big")));
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(33)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Tag size is too big")));
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacTagSizeInBytes(65)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Tag size is too big")));
}

TEST(AesCtrHmacStreamingParametersTest, BuildWithoutSettingSegmentSizeFails) {
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(32)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Ciphertext segment size must be set")));
}

TEST(AesCtrHmacStreamingParametersTest, BuildWithInvalidSegmentSizeFails) {
  // Min ciphertext segment size = derived key size + tag size + 9
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(32)
          .SetCiphertextSegmentSizeInBytes(57)
          .Build(),
      IsOk());
  EXPECT_THAT(
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(32)
          .SetCiphertextSegmentSizeInBytes(56)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Ciphertext segment size must be at least 57 bytes")));
}

TEST(AesCtrHmacStreamingParametersTest, CopyConstructor) {
  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  AesCtrHmacStreamingParameters copy(*parameters);

  EXPECT_THAT(copy.KeySizeInBytes(), Eq(35));
  EXPECT_THAT(copy.DerivedKeySizeInBytes(), Eq(32));
  EXPECT_THAT(copy.HkdfHashType(),
              Eq(AesCtrHmacStreamingParameters::HashType::kSha512));
  EXPECT_THAT(copy.HmacHashType(),
              Eq(AesCtrHmacStreamingParameters::HashType::kSha256));
  EXPECT_THAT(copy.HmacTagSizeInBytes(), Eq(16));
  EXPECT_THAT(copy.CiphertextSegmentSizeInBytes(), Eq(1024));
}

TEST(AesCtrHmacStreamingParametersTest, CopyAssignment) {
  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  AesCtrHmacStreamingParameters copy = *parameters;

  EXPECT_THAT(copy.KeySizeInBytes(), Eq(35));
  EXPECT_THAT(copy.DerivedKeySizeInBytes(), Eq(32));
  EXPECT_THAT(copy.HkdfHashType(),
              Eq(AesCtrHmacStreamingParameters::HashType::kSha512));
  EXPECT_THAT(copy.HmacHashType(),
              Eq(AesCtrHmacStreamingParameters::HashType::kSha256));
  EXPECT_THAT(copy.HmacTagSizeInBytes(), Eq(16));
  EXPECT_THAT(copy.CiphertextSegmentSizeInBytes(), Eq(1024));
}

TEST_P(AesCtrHmacStreamingParametersTest, ParametersEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetDerivedKeySizeInBytes(test_case.derived_key_size)
          .SetHkdfHashType(test_case.hkdf_hash_type)
          .SetHmacHashType(test_case.hmac_hash_type)
          .SetHmacTagSizeInBytes(test_case.tag_size)
          .SetCiphertextSegmentSizeInBytes(test_case.segment_size)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacStreamingParameters> other_parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetDerivedKeySizeInBytes(test_case.derived_key_size)
          .SetHkdfHashType(test_case.hkdf_hash_type)
          .SetHmacHashType(test_case.hmac_hash_type)
          .SetHmacTagSizeInBytes(test_case.tag_size)
          .SetCiphertextSegmentSizeInBytes(test_case.segment_size)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(AesCtrHmacStreamingParametersTest, KeySizeNotEqual) {
  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacStreamingParameters> other_parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(36)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesCtrHmacStreamingParametersTest, DerivedKeySizeNotEqual) {
  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacStreamingParameters> other_parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesCtrHmacStreamingParametersTest, HkdfHashTypeNotEqual) {
  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacStreamingParameters> other_parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesCtrHmacStreamingParametersTest, HmacHashTypeNotEqual) {
  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacStreamingParameters> other_parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesCtrHmacStreamingParametersTest, HmacTagSizeNotEqual) {
  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacStreamingParameters> other_parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(17)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesCtrHmacStreamingParametersTest, CiphertextSegmentSizeNotEqual) {
  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacStreamingParameters> other_parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(2 * 1024)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesCtrHmacStreamingParametersTest, Clone) {
  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha512)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  ASSERT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
