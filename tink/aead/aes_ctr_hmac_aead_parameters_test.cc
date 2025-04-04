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

#include "tink/aead/aes_ctr_hmac_aead_parameters.h"

#include <memory>
#include <utility>

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

struct BuildTestCase {
  int aes_key_size;
  int hmac_key_size;
  int iv_size;
  int tag_size;
  AesCtrHmacAeadParameters::HashType hash_type;
  AesCtrHmacAeadParameters::Variant variant;
  bool has_id_requirement;
};

using AesCtrHmacAeadParametersTest = TestWithParam<BuildTestCase>;

INSTANTIATE_TEST_SUITE_P(
    AesCtrHmacAeadParametersBuildTestSuite, AesCtrHmacAeadParametersTest,
    Values(BuildTestCase{/*aes_key_size=*/16, /*hmac_key_size=*/16,
                         /*iv_size=*/12, /*tag_size=*/28,
                         AesCtrHmacAeadParameters::HashType::kSha256,
                         AesCtrHmacAeadParameters::Variant::kTink,
                         /*has_id_requirement=*/true},
           BuildTestCase{/*aes_key_size=*/24, /*hmac_key_size=*/32,
                         /*iv_size=*/16, /*tag_size=*/32,
                         AesCtrHmacAeadParameters::HashType::kSha384,
                         AesCtrHmacAeadParameters::Variant::kCrunchy,
                         /*has_id_requirement=*/true},
           BuildTestCase{/*aes_key_size=*/32, /*hmac_key_size=*/16,
                         /*iv_size=*/16, /*tag_size=*/48,
                         AesCtrHmacAeadParameters::HashType::kSha512,
                         AesCtrHmacAeadParameters::Variant::kNoPrefix,
                         /*has_id_requirement=*/false}));

TEST_P(AesCtrHmacAeadParametersTest, BuildParametersSucceeds) {
  BuildTestCase test_case = GetParam();

  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(test_case.aes_key_size)
          .SetHmacKeySizeInBytes(test_case.hmac_key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetAesKeySizeInBytes(), Eq(test_case.aes_key_size));
  EXPECT_THAT(parameters->GetHmacKeySizeInBytes(), Eq(test_case.hmac_key_size));
  EXPECT_THAT(parameters->GetIvSizeInBytes(), Eq(test_case.iv_size));
  EXPECT_THAT(parameters->GetTagSizeInBytes(), Eq(test_case.tag_size));
  EXPECT_THAT(parameters->GetHashType(), Eq(test_case.hash_type));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithoutSettingAesKeySizeFails) {
  EXPECT_THAT(AesCtrHmacAeadParameters::Builder()
                  .SetHmacKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(32)
                  .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
                  .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("AES key size is not set")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithInvalidAesKeySizeFails) {
  EXPECT_THAT(
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(17)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("AES key size should be 16, 24, or 32 bytes")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithoutSettingAHmacKeySizeFails) {
  EXPECT_THAT(AesCtrHmacAeadParameters::Builder()
                  .SetAesKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(32)
                  .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
                  .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("HMAC key size is not set")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithInvalidHmacKeySizeFails) {
  EXPECT_THAT(
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(15)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("HMAC key size should have at least 16 bytes")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithoutSettingIvSizeFails) {
  EXPECT_THAT(AesCtrHmacAeadParameters::Builder()
                  .SetAesKeySizeInBytes(16)
                  .SetHmacKeySizeInBytes(16)
                  .SetTagSizeInBytes(32)
                  .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
                  .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("IV size is not set")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithTooSmallIvSizeFails) {
  EXPECT_THAT(AesCtrHmacAeadParameters::Builder()
                  .SetAesKeySizeInBytes(16)
                  .SetHmacKeySizeInBytes(16)
                  .SetIvSizeInBytes(11)
                  .SetTagSizeInBytes(32)
                  .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
                  .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("IV size should be betwwen 12 and 16 bytes")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithTooBigIvSizeFails) {
  EXPECT_THAT(AesCtrHmacAeadParameters::Builder()
                  .SetAesKeySizeInBytes(16)
                  .SetHmacKeySizeInBytes(16)
                  .SetIvSizeInBytes(17)
                  .SetTagSizeInBytes(32)
                  .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
                  .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("IV size should be betwwen 12 and 16 bytes")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithoutSettingTagSizeFails) {
  EXPECT_THAT(AesCtrHmacAeadParameters::Builder()
                  .SetAesKeySizeInBytes(16)
                  .SetHmacKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
                  .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Tag size is not set")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithTooSmallTagSizeFails) {
  EXPECT_THAT(AesCtrHmacAeadParameters::Builder()
                  .SetAesKeySizeInBytes(16)
                  .SetHmacKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(9)
                  .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
                  .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Tag size should have at least 10 bytes")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithTooBigTagSizeSHA1Fails) {
  EXPECT_THAT(
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(21)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha1)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Tag size 21 is too big for given hash type")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithTooBigTagSizeSHA224Fails) {
  EXPECT_THAT(
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(29)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha224)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Tag size 29 is too big for given hash type")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithTooBigTagSizeSHA256Fails) {
  EXPECT_THAT(
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(33)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Tag size 33 is too big for given hash type")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithTooBigTagSizeSHA384Fails) {
  EXPECT_THAT(
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(49)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha384)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Tag size 49 is too big for given hash type")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithTooBigTagSizeSHA512Fails) {
  EXPECT_THAT(AesCtrHmacAeadParameters::Builder()
                  .SetAesKeySizeInBytes(16)
                  .SetHmacKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(65)
                  .SetHashType(AesCtrHmacAeadParameters::HashType::kSha512)
                  .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithoutSettingHashTypeFails) {
  EXPECT_THAT(AesCtrHmacAeadParameters::Builder()
                  .SetAesKeySizeInBytes(16)
                  .SetHmacKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(32)
                  .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Hash type is not set")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithInvalidHashTypeFails) {
  EXPECT_THAT(AesCtrHmacAeadParameters::Builder()
                  .SetAesKeySizeInBytes(16)
                  .SetHmacKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(32)
                  .SetHashType(
                      AesCtrHmacAeadParameters::HashType::
                          kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
                  .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("unknown hash type")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithoutSettingVariantFails) {
  EXPECT_THAT(AesCtrHmacAeadParameters::Builder()
                  .SetAesKeySizeInBytes(16)
                  .SetHmacKeySizeInBytes(16)
                  .SetIvSizeInBytes(16)
                  .SetTagSizeInBytes(32)
                  .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Variant is not set")));
}

TEST(AesCtrHmacAeadParametersTest, BuildWithInvalidVariantFails) {
  EXPECT_THAT(
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::
                          kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .Build()
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("unknown Variant")));
}

TEST(AesCtrHmacAeadParametersTest, CopyConstructor) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  AesCtrHmacAeadParameters copy(*parameters);

  EXPECT_THAT(copy.GetAesKeySizeInBytes(), Eq(16));
  EXPECT_THAT(copy.GetHmacKeySizeInBytes(), Eq(16));
  EXPECT_THAT(copy.GetIvSizeInBytes(), Eq(16));
  EXPECT_THAT(copy.GetTagSizeInBytes(), Eq(32));
  EXPECT_THAT(copy.GetHashType(),
              Eq(AesCtrHmacAeadParameters::HashType::kSha256));
  EXPECT_THAT(copy.GetVariant(),
              Eq(AesCtrHmacAeadParameters::Variant::kNoPrefix));
  EXPECT_THAT(copy.HasIdRequirement(), IsFalse());
}

TEST(AesCtrHmacAeadParametersTest, CopyAssignment) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacAeadParameters> copy =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(64)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha512)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(copy, IsOk());

  *copy = *parameters;

  EXPECT_THAT(copy->GetAesKeySizeInBytes(), Eq(16));
  EXPECT_THAT(copy->GetHmacKeySizeInBytes(), Eq(16));
  EXPECT_THAT(copy->GetIvSizeInBytes(), Eq(16));
  EXPECT_THAT(copy->GetTagSizeInBytes(), Eq(32));
  EXPECT_THAT(copy->GetHashType(),
              Eq(AesCtrHmacAeadParameters::HashType::kSha256));
  EXPECT_THAT(copy->GetVariant(),
              Eq(AesCtrHmacAeadParameters::Variant::kNoPrefix));
  EXPECT_THAT(copy->HasIdRequirement(), IsFalse());
}

TEST(AesCtrHmacAeadParametersTest, MoveConstructor) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  AesCtrHmacAeadParameters move(std::move(*parameters));

  EXPECT_THAT(move.GetAesKeySizeInBytes(), Eq(16));
  EXPECT_THAT(move.GetHmacKeySizeInBytes(), Eq(16));
  EXPECT_THAT(move.GetIvSizeInBytes(), Eq(16));
  EXPECT_THAT(move.GetTagSizeInBytes(), Eq(32));
  EXPECT_THAT(move.GetHashType(),
              Eq(AesCtrHmacAeadParameters::HashType::kSha256));
  EXPECT_THAT(move.GetVariant(),
              Eq(AesCtrHmacAeadParameters::Variant::kNoPrefix));
  EXPECT_THAT(move.HasIdRequirement(), IsFalse());
}

TEST(AesCtrHmacAeadParametersTest, MoveAssignment) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacAeadParameters> move =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(64)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha512)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(move, IsOk());

  *move = std::move(*parameters);

  EXPECT_THAT(move->GetAesKeySizeInBytes(), Eq(16));
  EXPECT_THAT(move->GetHmacKeySizeInBytes(), Eq(16));
  EXPECT_THAT(move->GetIvSizeInBytes(), Eq(16));
  EXPECT_THAT(move->GetTagSizeInBytes(), Eq(32));
  EXPECT_THAT(move->GetHashType(),
              Eq(AesCtrHmacAeadParameters::HashType::kSha256));
  EXPECT_THAT(move->GetVariant(),
              Eq(AesCtrHmacAeadParameters::Variant::kNoPrefix));
  EXPECT_THAT(move->HasIdRequirement(), IsFalse());
}

TEST_P(AesCtrHmacAeadParametersTest, SameParametersEquals) {
  BuildTestCase test_case = GetParam();
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(test_case.aes_key_size)
          .SetHmacKeySizeInBytes(test_case.hmac_key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacAeadParameters> other_parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(test_case.aes_key_size)
          .SetHmacKeySizeInBytes(test_case.hmac_key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(AesCtrHmacAeadParametersTest, DifferentAesKeySizeNotEqual) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacAeadParameters> other_parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(24)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesCtrHmacAeadParametersTest, DifferentHmacKeySizeNotEqual) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacAeadParameters> other_parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesCtrHmacAeadParametersTest, DifferentIvSizeNotEqual) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacAeadParameters> other_parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesCtrHmacAeadParametersTest, DifferentTagSizeNotEqual) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacAeadParameters> other_parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesCtrHmacAeadParametersTest, DifferentHashTypeNotEqual) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacAeadParameters> other_parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha512)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesCtrHmacAeadParametersTest, DifferentVariantNotEqual) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesCtrHmacAeadParameters> other_parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kCrunchy)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(AesCtrHmacAeadParametersTest, Clone) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  ASSERT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
