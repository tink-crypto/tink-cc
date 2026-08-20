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

#include "tink/daead/aes_siv_key.h"

#include <memory>
#include <optional>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/types/optional.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/daead/internal/aes_siv_test_vectors.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using AesSivKeyTest = TestWithParam<internal::AesSivTestVector>;

INSTANTIATE_TEST_SUITE_P(AesSivKeyTestSuite, AesSivKeyTest,
                         ValuesIn(internal::CreateAesSivTestVectors()));

TEST_P(AesSivKeyTest, CreateSucceeds) {
  const internal::AesSivTestVector& test_vector = GetParam();

  absl::StatusOr<AesSivKey> key = AesSivKey::Create(
      test_vector.key.GetParameters(),
      test_vector.key.GetKeyBytes(GetPartialKeyAccess()),
      test_vector.key.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(test_vector.key.GetParameters()));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_vector.key.GetIdRequirement()));
  EXPECT_THAT(key->GetOutputPrefix(), Eq(test_vector.key.GetOutputPrefix()));
  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()),
              Eq(test_vector.key.GetKeyBytes(GetPartialKeyAccess())));
}

TEST(AesSivKeyTest, CreateKeyWithMismatchedKeySizeFails) {
  // Key size parameter is 64 bytes.
  absl::StatusOr<AesSivParameters> params = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  // Key material is 32 bytes (another valid key length).
  RestrictedData mismatched_secret =
      internal::GetAesSivTestVector(32, AesSivParameters::Variant::kNoPrefix)
          .key.GetKeyBytes(GetPartialKeyAccess());

  EXPECT_THAT(AesSivKey::Create(*params, mismatched_secret,
                                /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesSivKeyTest, CreateKeyWithInvalidIdRequirementFails) {
  absl::StatusOr<AesSivParameters> no_prefix_params = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_params, IsOk());

  absl::StatusOr<AesSivParameters> tink_params = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  RestrictedData secret =
      internal::GetAesSivTestVector(64, AesSivParameters::Variant::kNoPrefix)
          .key.GetKeyBytes(GetPartialKeyAccess());

  EXPECT_THAT(AesSivKey::Create(*no_prefix_params, secret,
                                /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      AesSivKey::Create(*tink_params, secret,
                        /*id_requirement=*/std::nullopt, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesSivKeyTest, KeyEquals) {
  const internal::AesSivTestVector& test_vector = GetParam();

  absl::StatusOr<AesSivKey> key = AesSivKey::Create(
      test_vector.key.GetParameters(),
      test_vector.key.GetKeyBytes(GetPartialKeyAccess()),
      test_vector.key.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesSivKey> other_key = AesSivKey::Create(
      test_vector.key.GetParameters(),
      test_vector.key.GetKeyBytes(GetPartialKeyAccess()),
      test_vector.key.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(AesSivKeyTest, DifferentVariantNotEqual) {
  const AesSivKey& crunchy_key =
      internal::GetAesSivTestVector(64, AesSivParameters::Variant::kCrunchy)
          .key;
  const AesSivKey& tink_key =
      internal::GetAesSivTestVector(64, AesSivParameters::Variant::kTink).key;

  EXPECT_TRUE(crunchy_key != tink_key);
  EXPECT_TRUE(tink_key != crunchy_key);
  EXPECT_FALSE(crunchy_key == tink_key);
  EXPECT_FALSE(tink_key == crunchy_key);
}

TEST(AesSivKeyTest, DifferentSecretDataNotEqual) {
  absl::StatusOr<AesSivParameters> params = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret1 =
      internal::GetAesSivTestVector(64, AesSivParameters::Variant::kTink)
          .key.GetKeyBytes(GetPartialKeyAccess());
  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/64);

  absl::StatusOr<AesSivKey> key = AesSivKey::Create(
      *params, secret1, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesSivKey> other_key = AesSivKey::Create(
      *params, secret2, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesSivKeyTest, DifferentIdRequirementNotEqual) {
  absl::StatusOr<AesSivParameters> params = AesSivParameters::Create(
      /*key_size_in_bytes=*/64, AesSivParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret =
      internal::GetAesSivTestVector(64, AesSivParameters::Variant::kTink)
          .key.GetKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<AesSivKey> key = AesSivKey::Create(
      *params, secret, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesSivKey> other_key = AesSivKey::Create(
      *params, secret, /*id_requirement=*/0x02030405, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesSivKeyTest, CopyConstructor) {
  const AesSivKey& key =
      internal::GetAesSivTestVector(64, AesSivParameters::Variant::kTink).key;

  AesSivKey copy(key);

  EXPECT_THAT(copy, Eq(key));
}

TEST(AesSivKeyTest, CopyAssignment) {
  const AesSivKey& key =
      internal::GetAesSivTestVector(64, AesSivParameters::Variant::kTink).key;
  const AesSivKey& other_key =
      internal::GetAesSivTestVector(32, AesSivParameters::Variant::kNoPrefix)
          .key;

  AesSivKey copy = other_key;
  copy = key;

  EXPECT_THAT(copy, Eq(key));
}

TEST(AesSivKeyTest, MoveConstructor) {
  AesSivKey key =
      internal::GetAesSivTestVector(64, AesSivParameters::Variant::kTink).key;

  AesSivKey expected = key;
  AesSivKey moved(std::move(key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(AesSivKeyTest, MoveAssignment) {
  AesSivKey key =
      internal::GetAesSivTestVector(64, AesSivParameters::Variant::kTink).key;
  AesSivKey other_key =
      internal::GetAesSivTestVector(32, AesSivParameters::Variant::kNoPrefix)
          .key;

  AesSivKey expected = key;
  other_key = std::move(key);

  EXPECT_THAT(other_key, Eq(expected));
}

TEST(AesSivKeyTest, Clone) {
  const AesSivKey& key =
      internal::GetAesSivTestVector(64, AesSivParameters::Variant::kTink).key;

  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
