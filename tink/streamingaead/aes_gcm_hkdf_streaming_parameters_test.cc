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

#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"

#include <memory>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
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
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  int key_size;
  int derived_key_size;
  AesGcmHkdfStreamingParameters::HashType hash_type;
  int segment_size;
};

using AesGcmHkdfStreamingParametersTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    BuildTestSuite, AesGcmHkdfStreamingParametersTest,
    Values(
        TestCase{/*key_size=*/19, /*derived_key_size=*/16,
                 /*hash_type=*/AesGcmHkdfStreamingParameters::HashType::kSha1,
                 /*segment_size=*/1024},
        TestCase{/*key_size=*/19, /*derived_key_size=*/16,
                 /*hash_type=*/AesGcmHkdfStreamingParameters::HashType::kSha256,
                 /*segment_size=*/1024 * 1024},
        TestCase{/*key_size=*/35, /*derived_key_size=*/32,
                 /*hash_type=*/AesGcmHkdfStreamingParameters::HashType::kSha512,
                 /*segment_size=*/3 * 1024 * 1024},
        TestCase{/*key_size=*/35, /*derived_key_size=*/32,
                 /*hash_type=*/AesGcmHkdfStreamingParameters::HashType::kSha512,
                 /*segment_size=*/4 * 1024 * 1024}));

TEST_P(AesGcmHkdfStreamingParametersTest, Build) {
  TestCase test_case = GetParam();

  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetDerivedKeySizeInBytes(test_case.derived_key_size)
          .SetHashType(test_case.hash_type)
          .SetCiphertextSegmentSizeInBytes(test_case.segment_size)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->KeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(parameters->DerivedKeySizeInBytes(),
              Eq(test_case.derived_key_size));
  EXPECT_THAT(parameters->GetHashType(), Eq(test_case.hash_type));
  EXPECT_THAT(parameters->CiphertextSegmentSizeInBytes(),
              Eq(test_case.segment_size));
  EXPECT_THAT(parameters->HasIdRequirement(), IsFalse());
}

TEST(AesGcmHkdfStreamingParametersTest, BuildWithoutSettingKeySizeFails) {
  EXPECT_THAT(AesGcmHkdfStreamingParameters::Builder()
                  .SetDerivedKeySizeInBytes(16)
                  .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
                  .SetCiphertextSegmentSizeInBytes(1024)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Key size must be set")));
}

TEST(AesGcmHkdfStreamingParametersTest, BuildWithInvalidKeySizeFails) {
  EXPECT_THAT(
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(15)
          .SetDerivedKeySizeInBytes(16)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Key size must be at least the derived key size")));
  EXPECT_THAT(
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(31)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Key size must be at least the derived key size")));
}

TEST(AesGcmHkdfStreamingParametersTest,
     BuildWithoutSettingDerivedKeySizeFails) {
  EXPECT_THAT(AesGcmHkdfStreamingParameters::Builder()
                  .SetKeySizeInBytes(19)
                  .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
                  .SetCiphertextSegmentSizeInBytes(1024)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Derived key size must be set")));
}

TEST(AesGcmHkdfStreamingParametersTest, BuildWithInvalidDerivedKeySizeFails) {
  EXPECT_THAT(
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(17)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Derived key size must be either 16 or 32 bytes")));
  EXPECT_THAT(
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(33)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Derived key size must be either 16 or 32 bytes")));
}

TEST(AesGcmHkdfStreamingParametersTest, BuildWithoutSettingHashTypeFails) {
  EXPECT_THAT(AesGcmHkdfStreamingParameters::Builder()
                  .SetKeySizeInBytes(19)
                  .SetDerivedKeySizeInBytes(16)
                  .SetCiphertextSegmentSizeInBytes(1024)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Hash type must be set")));
}

TEST(AesGcmHkdfStreamingParametersTest, BuildWithInvalidHashTypeFails) {
  EXPECT_THAT(AesGcmHkdfStreamingParameters::Builder()
                  .SetKeySizeInBytes(19)
                  .SetDerivedKeySizeInBytes(16)
                  .SetHashType(
                      AesGcmHkdfStreamingParameters::HashType::
                          kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
                  .SetCiphertextSegmentSizeInBytes(1024)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Hash type not supported")));
}

TEST(AesGcmHkdfStreamingParametersTest, BuildWithoutSettingSegmentSizeFails) {
  EXPECT_THAT(AesGcmHkdfStreamingParameters::Builder()
                  .SetKeySizeInBytes(19)
                  .SetDerivedKeySizeInBytes(16)
                  .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Ciphertext segment size must be set")));
}

TEST(AesGcmHkdfStreamingParametersTest, BuildWithMinimumSegmentSize) {
  // Min ciphertext segment size = derived key size + 24
  EXPECT_THAT(AesGcmHkdfStreamingParameters::Builder()
                  .SetKeySizeInBytes(19)
                  .SetDerivedKeySizeInBytes(16)
                  .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
                  .SetCiphertextSegmentSizeInBytes(40)
                  .Build(),
              IsOk());
}

TEST(AesGcmHkdfStreamingParametersTest, BuildWithInvalidSegmentSizeFails) {
  // Min ciphertext segment size = derived key size + 24
  EXPECT_THAT(
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
          .SetCiphertextSegmentSizeInBytes(39)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Ciphertext segment size must be at least 40 bytes")));
}

TEST(AesGcmHkdfStreamingParametersTest, CopyConstructor) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  AesGcmHkdfStreamingParameters copy(*parameters);

  EXPECT_THAT(copy, Eq(*parameters));
}

TEST(AesGcmHkdfStreamingParametersTest, CopyAssignment) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesGcmHkdfStreamingParameters> copy =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(copy, IsOk());
  ASSERT_THAT(*copy, Not(Eq(*parameters)));

  *copy = *parameters;

  EXPECT_THAT(*copy, Eq(*parameters));
}

TEST(AesGcmHkdfStreamingParametersTest, MoveConstructor) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  AesGcmHkdfStreamingParameters move(std::move(*parameters));

  EXPECT_THAT(move.KeySizeInBytes(), Eq(35));
  EXPECT_THAT(move.DerivedKeySizeInBytes(), Eq(32));
  EXPECT_THAT(move.GetHashType(),
              Eq(AesGcmHkdfStreamingParameters::HashType::kSha512));
  EXPECT_THAT(move.CiphertextSegmentSizeInBytes(), Eq(1024));
}

TEST(AesGcmHkdfStreamingParametersTest, MoveAssignment) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesGcmHkdfStreamingParameters> move =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
          .SetCiphertextSegmentSizeInBytes(512)
          .Build();
  ASSERT_THAT(move, IsOk());
  ASSERT_THAT(*move, Not(Eq(*parameters)));

  *move = std::move(*parameters);

  EXPECT_THAT(move->KeySizeInBytes(), Eq(35));
  EXPECT_THAT(move->DerivedKeySizeInBytes(), Eq(32));
  EXPECT_THAT(move->GetHashType(),
              Eq(AesGcmHkdfStreamingParameters::HashType::kSha512));
  EXPECT_THAT(move->CiphertextSegmentSizeInBytes(), Eq(1024));
}

TEST_P(AesGcmHkdfStreamingParametersTest, ParametersEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetDerivedKeySizeInBytes(test_case.derived_key_size)
          .SetHashType(test_case.hash_type)
          .SetCiphertextSegmentSizeInBytes(test_case.segment_size)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesGcmHkdfStreamingParameters> other_parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetDerivedKeySizeInBytes(test_case.derived_key_size)
          .SetHashType(test_case.hash_type)
          .SetCiphertextSegmentSizeInBytes(test_case.segment_size)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(AesGcmHkdfStreamingParametersTest, KeySizeNotEqual) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesGcmHkdfStreamingParameters> other_parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(36)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesGcmHkdfStreamingParametersTest, DerivedKeySizeNotEqual) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesGcmHkdfStreamingParameters> other_parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(16)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesGcmHkdfStreamingParametersTest, HashTypeNotEqual) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesGcmHkdfStreamingParameters> other_parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesGcmHkdfStreamingParametersTest, CiphertextSegmentSizeNotEqual) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesGcmHkdfStreamingParameters> other_parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(2 * 1024)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesGcmHkdfStreamingParametersTest, Clone) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  ASSERT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
