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

#include "tink/aead/aes_gcm_siv_key.h"

#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
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
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  AesGcmSivParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using AesGcmSivKeyTest = TestWithParam<std::tuple<int, TestCase>>;

INSTANTIATE_TEST_SUITE_P(
    AesGcmSivKeyTestSuite, AesGcmSivKeyTest,
    Combine(Values(16, 32),
            Values(TestCase{AesGcmSivParameters::Variant::kTink, 0x02030400,
                            std::string("\x01\x02\x03\x04\x00", 5)},
                   TestCase{AesGcmSivParameters::Variant::kCrunchy, 0x01030005,
                            std::string("\x00\x01\x03\x00\x05", 5)},
                   TestCase{AesGcmSivParameters::Variant::kNoPrefix,
                            absl::nullopt, ""})));

TEST_P(AesGcmSivKeyTest, CreateSucceeds) {
  int key_size;
  TestCase test_case;
  std::tie(key_size, test_case) = GetParam();

  absl::StatusOr<AesGcmSivParameters> params =
      AesGcmSivParameters::Create(key_size, test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);
  absl::StatusOr<AesGcmSivKey> key = AesGcmSivKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*params));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetOutputPrefix(), Eq(test_case.output_prefix));
}

TEST(AesGcmSivKeyTest, CreateKeyWithMismatchedKeySizeFails) {
  // Key size parameter is 32 bytes.
  absl::StatusOr<AesGcmSivParameters> params = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/32, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  // Key material is 16 bytes (another valid key length).
  RestrictedData mismatched_secret = RestrictedData(/*num_random_bytes=*/16);

  EXPECT_THAT(
      AesGcmSivKey::Create(*params, mismatched_secret,
                           /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesGcmSivKeyTest, CreateKeyWithInvalidIdRequirementFails) {
  absl::StatusOr<AesGcmSivParameters> no_prefix_params =
      AesGcmSivParameters::Create(/*key_size_in_bytes=*/32,
                                  AesGcmSivParameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_params, IsOk());

  absl::StatusOr<AesGcmSivParameters> tink_params = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/32, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(
      AesGcmSivKey::Create(*no_prefix_params, secret,
                           /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesGcmSivKey::Create(*tink_params, secret,
                                   /*id_requirement=*/absl::nullopt,
                                   GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesGcmSivKeyTest, GetKeyBytes) {
  int key_size;
  TestCase test_case;
  std::tie(key_size, test_case) = GetParam();

  absl::StatusOr<AesGcmSivParameters> params =
      AesGcmSivParameters::Create(key_size, test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);

  absl::StatusOr<AesGcmSivKey> key = AesGcmSivKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
}

TEST_P(AesGcmSivKeyTest, KeyEquals) {
  int key_size;
  TestCase test_case;
  std::tie(key_size, test_case) = GetParam();

  absl::StatusOr<AesGcmSivParameters> params =
      AesGcmSivParameters::Create(key_size, test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(key_size);
  absl::StatusOr<AesGcmSivKey> key = AesGcmSivKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesGcmSivKey> other_key = AesGcmSivKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(AesGcmSivKeyTest, DifferentVariantNotEqual) {
  absl::StatusOr<AesGcmSivParameters> crunchy_params =
      AesGcmSivParameters::Create(/*key_size_in_bytes=*/32,
                                  AesGcmSivParameters::Variant::kCrunchy);
  ASSERT_THAT(crunchy_params, IsOk());

  absl::StatusOr<AesGcmSivParameters> tink_params = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/32, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmSivKey> key = AesGcmSivKey::Create(
      *crunchy_params, secret, /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesGcmSivKey> other_key =
      AesGcmSivKey::Create(*tink_params, secret, /*id_requirement=*/0x01020304,
                           GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesGcmSivKeyTest, DifferentSecretDataNotEqual) {
  absl::StatusOr<AesGcmSivParameters> params = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/32, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmSivKey> key = AesGcmSivKey::Create(
      *params, secret1, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesGcmSivKey> other_key = AesGcmSivKey::Create(
      *params, secret2, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesGcmSivKeyTest, DifferentIdRequirementNotEqual) {
  absl::StatusOr<AesGcmSivParameters> params = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/32, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmSivKey> key = AesGcmSivKey::Create(
      *params, secret, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesGcmSivKey> other_key = AesGcmSivKey::Create(
      *params, secret, /*id_requirement=*/0x02030405, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesGcmSivKeyTest, CopyConstructor) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmSivParameters> parameters = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/32, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesGcmSivKey> key = AesGcmSivKey::Create(
      *parameters, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  AesGcmSivKey copy(*key);

  EXPECT_THAT(copy.GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(copy.GetParameters(), Eq(*parameters));
  EXPECT_THAT(copy.GetIdRequirement(), Eq(0x123));
}

TEST(AesGcmSivKeyTest, CopyAssignment) {
  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmSivParameters> parameters1 = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/32, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(parameters1, IsOk());

  absl::StatusOr<AesGcmSivKey> key = AesGcmSivKey::Create(
      *parameters1, secret1, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/16);

  absl::StatusOr<AesGcmSivParameters> parameters2 = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/16, AesGcmSivParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters2, IsOk());

  absl::StatusOr<AesGcmSivKey> copy = AesGcmSivKey::Create(
      *parameters2, secret2, /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *key;

  EXPECT_THAT(copy->GetKeyBytes(GetPartialKeyAccess()), Eq(secret1));
  EXPECT_THAT(copy->GetParameters(), Eq(*parameters1));
  EXPECT_THAT(copy->GetIdRequirement(), Eq(0x123));
}

TEST(AesGcmSivKeyTest, MoveConstructor) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmSivParameters> parameters = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/32, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesGcmSivKey> key = AesGcmSivKey::Create(
      *parameters, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  AesGcmSivKey move(std::move(*key));

  EXPECT_THAT(move.GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(move.GetParameters(), Eq(*parameters));
  EXPECT_THAT(move.GetIdRequirement(), Eq(0x123));
}

TEST(AesGcmSivKeyTest, MoveAssignment) {
  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmSivParameters> parameters1 = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/32, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(parameters1, IsOk());

  absl::StatusOr<AesGcmSivKey> key = AesGcmSivKey::Create(
      *parameters1, secret1, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/16);

  absl::StatusOr<AesGcmSivParameters> parameters2 = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/16, AesGcmSivParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters2, IsOk());

  absl::StatusOr<AesGcmSivKey> move = AesGcmSivKey::Create(
      *parameters2, secret2, /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(move, IsOk());

  *move = std::move(*key);

  EXPECT_THAT(move->GetKeyBytes(GetPartialKeyAccess()), Eq(secret1));
  EXPECT_THAT(move->GetParameters(), Eq(*parameters1));
  EXPECT_THAT(move->GetIdRequirement(), Eq(0x123));
}

TEST(AesGcmSivKeyTest, Clone) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesGcmSivParameters> parameters = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/32, AesGcmSivParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesGcmSivKey> key = AesGcmSivKey::Create(
      *parameters, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
