// Copyright 2022 Google LLC
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

#include "tink/mac/aes_cmac_key.h"

#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/key.h"
#include "tink/mac/aes_cmac_parameters.h"
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
  AesCmacParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using AesCmacKeyTest = TestWithParam<std::tuple<int, int, TestCase>>;

INSTANTIATE_TEST_SUITE_P(
    AesCmacKeyTestSuite, AesCmacKeyTest,
    Combine(Values(16, 32), Range(10, 16),
            Values(TestCase{AesCmacParameters::Variant::kTink, 0x02030400,
                            std::string("\x01\x02\x03\x04\x00", 5)},
                   TestCase{AesCmacParameters::Variant::kCrunchy, 0x01030005,
                            std::string("\x00\x01\x03\x00\x05", 5)},
                   TestCase{AesCmacParameters::Variant::kLegacy, 0x01020304,
                            std::string("\x00\x01\x02\x03\x04", 5)},
                   TestCase{AesCmacParameters::Variant::kNoPrefix,
                            absl::nullopt, ""})));

TEST_P(AesCmacKeyTest, CreateSucceeds) {
  int key_size;
  int cryptographic_tag_size;
  TestCase test_case;
  std::tie(key_size, cryptographic_tag_size, test_case) = GetParam();

  absl::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      key_size, cryptographic_tag_size, test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);
  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key.status(), IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*params));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetOutputPrefix(), Eq(test_case.output_prefix));
}

TEST(AesCmacKeyTest, CreateKeyWithMismatchedKeySizeFails) {
  // Key size parameter is 32 bytes.
  absl::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      /*key_size_in_bytes=*/32,
      /*cryptographic_tag_size_in_bytes=*/16,
      AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  // Key material is 16 bytes (another valid key length).
  RestrictedData mismatched_secret = RestrictedData(/*num_random_bytes=*/16);

  EXPECT_THAT(AesCmacKey::Create(*params, mismatched_secret,
                                 /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCmacKeyTest, CreateKeyWithWrongIdRequirementFails) {
  absl::StatusOr<AesCmacParameters> no_prefix_params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_params, IsOk());

  absl::StatusOr<AesCmacParameters> tink_params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(AesCmacKey::Create(*no_prefix_params, secret,
                                 /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesCmacKey::Create(*tink_params, secret,
                                 /*id_requirement=*/absl::nullopt,
                                 GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesCmacKeyTest, GetAesCmacKey) {
  int key_size;
  int cryptographic_tag_size;
  TestCase test_case;
  std::tie(key_size, cryptographic_tag_size, test_case) = GetParam();

  absl::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      key_size, cryptographic_tag_size, test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);

  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key.status(), IsOk());

  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
}

TEST_P(AesCmacKeyTest, KeyEquals) {
  int key_size;
  int cryptographic_tag_size;
  TestCase test_case;
  std::tie(key_size, cryptographic_tag_size, test_case) = GetParam();

  absl::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      key_size, cryptographic_tag_size, test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);
  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesCmacKey> other_key = AesCmacKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(AesCmacKeyTest, DifferentFormatNotEqual) {
  absl::StatusOr<AesCmacParameters> legacy_params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kLegacy);
  ASSERT_THAT(legacy_params, IsOk());

  absl::StatusOr<AesCmacParameters> tink_params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesCmacKey> key =
      AesCmacKey::Create(*legacy_params, secret, /*id_requirement=*/0x01020304,
                         GetPartialKeyAccess());
  ASSERT_THAT(key.status(), IsOk());

  absl::StatusOr<AesCmacKey> other_key =
      AesCmacKey::Create(*tink_params, secret, /*id_requirement=*/0x01020304,
                         GetPartialKeyAccess());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesCmacKeyTest, DifferentSecretDataNotEqual) {
  absl::StatusOr<AesCmacParameters> params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *params, secret1, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key.status(), IsOk());

  absl::StatusOr<AesCmacKey> other_key = AesCmacKey::Create(
      *params, secret2, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesCmacKeyTest, DifferentIdRequirementNotEqual) {
  absl::StatusOr<AesCmacParameters> params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *params, secret, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key.status(), IsOk());

  absl::StatusOr<AesCmacKey> other_key = AesCmacKey::Create(
      *params, secret, /*id_requirement=*/0x02030405, GetPartialKeyAccess());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesCmacKeyTest, CopyConstructor) {
  absl::StatusOr<AesCmacParameters> params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *params, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  AesCmacKey copy(*key);

  EXPECT_THAT(copy.GetParameters(), Eq(*params));
  EXPECT_THAT(copy.GetIdRequirement(), Eq(0x123));
  EXPECT_THAT(copy.GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
}

TEST(AesCmacKeyTest, CopyAssigment) {
  absl::StatusOr<AesCmacParameters> params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *params, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesCmacParameters> params2 =
      AesCmacParameters::Create(/*key_size_in_bytes=*/16,
                                /*cryptographic_tag_size_in_bytes=*/12,
                                AesCmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(params2, IsOk());

  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/16);

  absl::StatusOr<AesCmacKey> copy =
      AesCmacKey::Create(*params2, secret2, /*id_requirement=*/absl::nullopt,
                         GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *key;

  EXPECT_THAT(copy->GetParameters(), Eq(*params));
  EXPECT_THAT(copy->GetIdRequirement(), Eq(0x123));
  EXPECT_THAT(copy->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
}

TEST(AesCmacKeyTest, MoveConstructor) {
  absl::StatusOr<AesCmacParameters> params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *params, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  AesCmacKey move(std::move(*key));

  EXPECT_THAT(move.GetParameters(), Eq(*params));
  EXPECT_THAT(move.GetIdRequirement(), Eq(0x123));
  EXPECT_THAT(move.GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
}

TEST(AesCmacKeyTest, MoveAssigment) {
  absl::StatusOr<AesCmacParameters> params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *params, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesCmacParameters> params2 =
      AesCmacParameters::Create(/*key_size_in_bytes=*/16,
                                /*cryptographic_tag_size_in_bytes=*/12,
                                AesCmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(params2, IsOk());

  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/16);

  absl::StatusOr<AesCmacKey> move =
      AesCmacKey::Create(*params2, secret2, /*id_requirement=*/absl::nullopt,
                         GetPartialKeyAccess());
  ASSERT_THAT(move, IsOk());

  *move = std::move(*key);

  EXPECT_THAT(move->GetParameters(), Eq(*params));
  EXPECT_THAT(move->GetIdRequirement(), Eq(0x123));
  EXPECT_THAT(move->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
}

TEST(AesCmacKeyTest, Clone) {
  absl::StatusOr<AesCmacParameters> params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *params, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
