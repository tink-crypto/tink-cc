// Copyright 2023 Google LLC
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

#include "tink/aead/aes_gcm_key.h"

#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Combine;
using ::testing::Eq;
using ::testing::Range;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  AesGcmParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using AesGcmKeyTest = TestWithParam<std::tuple<int, int, TestCase>>;

INSTANTIATE_TEST_SUITE_P(
    AesGcmKeyTestSuite, AesGcmKeyTest,
    Combine(Values(16, 24, 32), Range(12, 16),
            Values(TestCase{AesGcmParameters::Variant::kTink, 0x02030400,
                            std::string("\x01\x02\x03\x04\x00", 5)},
                   TestCase{AesGcmParameters::Variant::kCrunchy, 0x01030005,
                            std::string("\x00\x01\x03\x00\x05", 5)},
                   TestCase{AesGcmParameters::Variant::kNoPrefix, absl::nullopt,
                            ""})));

TEST_P(AesGcmKeyTest, CreateSucceeds) {
  int key_size;
  int iv_and_tag_size;  // NOTE: There's no requirement for IV size == tag size.
  TestCase test_case;
  std::tie(key_size, iv_and_tag_size, test_case) = GetParam();

  absl::StatusOr<AesGcmParameters> params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(key_size)
          .SetIvSizeInBytes(iv_and_tag_size)
          .SetTagSizeInBytes(iv_and_tag_size)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);
  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*params));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetOutputPrefix(), Eq(test_case.output_prefix));
}

TEST(AesGcmKeyTest, CreateKeyWithMismatchedKeySizeFails) {
  // Key size parameter is 32 bytes.
  absl::StatusOr<AesGcmParameters> params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  // Key material is 16 bytes (another valid key length).
  RestrictedData mismatched_secret = RestrictedData(/*num_random_bytes=*/16);

  EXPECT_THAT(AesGcmKey::Create(*params, mismatched_secret,
                                /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmKeyTest, CreateKeyWithInvalidIdRequirementFails) {
  absl::StatusOr<AesGcmParameters> no_prefix_params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(no_prefix_params, IsOk());

  absl::StatusOr<AesGcmParameters> tink_params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(AesGcmKey::Create(*no_prefix_params, secret,
                                /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      AesGcmKey::Create(*tink_params, secret,
                        /*id_requirement=*/absl::nullopt, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesGcmKeyTest, GetKeyBytes) {
  int key_size;
  int iv_and_tag_size;  // NOTE: There's no requirement for IV size == tag size.
  TestCase test_case;
  std::tie(key_size, iv_and_tag_size, test_case) = GetParam();

  absl::StatusOr<AesGcmParameters> params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(key_size)
          .SetIvSizeInBytes(iv_and_tag_size)
          .SetTagSizeInBytes(iv_and_tag_size)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);

  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
}

TEST_P(AesGcmKeyTest, KeyEquals) {
  int key_size;
  int iv_and_tag_size;  // NOTE: There's no requirement for IV size == tag size.
  TestCase test_case;
  std::tie(key_size, iv_and_tag_size, test_case) = GetParam();

  absl::StatusOr<AesGcmParameters> params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(key_size)
          .SetIvSizeInBytes(iv_and_tag_size)
          .SetTagSizeInBytes(iv_and_tag_size)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);
  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesGcmKey> other_key = AesGcmKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(AesGcmKeyTest, DifferentVariantNotEqual) {
  absl::StatusOr<AesGcmParameters> crunchy_params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kCrunchy)
          .Build();
  ASSERT_THAT(crunchy_params, IsOk());

  absl::StatusOr<AesGcmParameters> tink_params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmKey> key =
      AesGcmKey::Create(*crunchy_params, secret, /*id_requirement=*/0x01020304,
                        GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesGcmKey> other_key =
      AesGcmKey::Create(*tink_params, secret, /*id_requirement=*/0x01020304,
                        GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesGcmKeyTest, DifferentSecretDataNotEqual) {
  absl::StatusOr<AesGcmParameters> params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *params, secret1, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesGcmKey> other_key = AesGcmKey::Create(
      *params, secret2, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesGcmKeyTest, DifferentIdRequirementNotEqual) {
  absl::StatusOr<AesGcmParameters> params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *params, secret, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesGcmKey> other_key = AesGcmKey::Create(
      *params, secret, /*id_requirement=*/0x02030405, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesGcmKeyTest, CopyConstructor) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *parameters, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  AesGcmKey copy(*key);

  EXPECT_THAT(copy.GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(copy.GetParameters(), Eq(*parameters));
  EXPECT_THAT(copy.GetIdRequirement(), Eq(0x123));
}

TEST(AesGcmKeyTest, CopyAssignment) {
  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmParameters> parameters1 =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters1, IsOk());

  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *parameters1, secret1, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/16);

  absl::StatusOr<AesGcmParameters> parameters2 =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(12)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters2, IsOk());

  absl::StatusOr<AesGcmKey> copy =
      AesGcmKey::Create(*parameters2, secret2, /*id_requirement=*/absl::nullopt,
                        GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *key;

  EXPECT_THAT(copy->GetKeyBytes(GetPartialKeyAccess()), Eq(secret1));
  EXPECT_THAT(copy->GetParameters(), Eq(*parameters1));
  EXPECT_THAT(copy->GetIdRequirement(), Eq(0x123));
}

TEST(AesGcmKeyTest, MoveConstructor) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *parameters, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  AesGcmKey move(std::move(*key));

  EXPECT_THAT(move.GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(move.GetParameters(), Eq(*parameters));
  EXPECT_THAT(move.GetIdRequirement(), Eq(0x123));
}

TEST(AesGcmKeyTest, MoveAssignment) {
  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmParameters> parameters1 =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters1, IsOk());

  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *parameters1, secret1, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/16);

  absl::StatusOr<AesGcmParameters> parameters2 =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(12)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters2, IsOk());

  absl::StatusOr<AesGcmKey> move =
      AesGcmKey::Create(*parameters2, secret2, /*id_requirement=*/absl::nullopt,
                        GetPartialKeyAccess());
  ASSERT_THAT(move, IsOk());

  *move = std::move(*key);

  EXPECT_THAT(move->GetKeyBytes(GetPartialKeyAccess()), Eq(secret1));
  EXPECT_THAT(move->GetParameters(), Eq(*parameters1));
  EXPECT_THAT(move->GetIdRequirement(), Eq(0x123));
}

TEST(AesGcmKeyTest, Clone) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *parameters, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
