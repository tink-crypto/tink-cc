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
#include <optional>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/aes_gcm_siv_test_vectors.h"
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

using AesGcmSivKeyTest = TestWithParam<internal::AeadTestVector>;

INSTANTIATE_TEST_SUITE_P(AesGcmSivKeyTestSuite, AesGcmSivKeyTest,
                         ValuesIn(internal::CreateAesGcmSivTestVectors()));

TEST_P(AesGcmSivKeyTest, CreateSucceeds) {
  const internal::AeadTestVector& test_vector = GetParam();
  const AesGcmSivKey& key =
      dynamic_cast<const AesGcmSivKey&>(*test_vector.aead_key);

  absl::StatusOr<AesGcmSivKey> created_key = AesGcmSivKey::Create(
      key.GetParameters(), key.GetKeyBytes(GetPartialKeyAccess()),
      key.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(created_key, IsOk());

  EXPECT_THAT(created_key->GetParameters(), Eq(key.GetParameters()));
  EXPECT_THAT(created_key->GetIdRequirement(), Eq(key.GetIdRequirement()));
  EXPECT_THAT(created_key->GetOutputPrefix(), Eq(key.GetOutputPrefix()));
  EXPECT_THAT(created_key->GetKeyBytes(GetPartialKeyAccess()),
              Eq(key.GetKeyBytes(GetPartialKeyAccess())));
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
                                   /*id_requirement=*/std::nullopt,
                                   GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesGcmSivKeyTest, KeyEquals) {
  const internal::AeadTestVector& test_vector = GetParam();
  const AesGcmSivKey& key =
      dynamic_cast<const AesGcmSivKey&>(*test_vector.aead_key);

  absl::StatusOr<AesGcmSivKey> created_key = AesGcmSivKey::Create(
      key.GetParameters(), key.GetKeyBytes(GetPartialKeyAccess()),
      key.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(created_key, IsOk());

  absl::StatusOr<AesGcmSivKey> other_key = AesGcmSivKey::Create(
      key.GetParameters(), key.GetKeyBytes(GetPartialKeyAccess()),
      key.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*created_key == *other_key);
  EXPECT_TRUE(*other_key == *created_key);
  EXPECT_FALSE(*created_key != *other_key);
  EXPECT_FALSE(*other_key != *created_key);
}

TEST(AesGcmSivKeyTest, DifferentVariantNotEqual) {
  const AesGcmSivKey& crunchy_key = dynamic_cast<const AesGcmSivKey&>(
      *internal::GetAesGcmSivTestVector(32,
                                        AesGcmSivParameters::Variant::kCrunchy)
           .aead_key);
  const AesGcmSivKey& tink_key = dynamic_cast<const AesGcmSivKey&>(
      *internal::GetAesGcmSivTestVector(32, AesGcmSivParameters::Variant::kTink)
           .aead_key);

  EXPECT_TRUE(crunchy_key != tink_key);
  EXPECT_TRUE(tink_key != crunchy_key);
  EXPECT_FALSE(crunchy_key == tink_key);
  EXPECT_FALSE(tink_key == crunchy_key);
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
  const AesGcmSivKey& key = dynamic_cast<const AesGcmSivKey&>(
      *internal::GetAesGcmSivTestVector(32, AesGcmSivParameters::Variant::kTink)
           .aead_key);

  AesGcmSivKey copy(key);

  EXPECT_THAT(copy, Eq(key));
}

TEST(AesGcmSivKeyTest, CopyAssignment) {
  const AesGcmSivKey& key = dynamic_cast<const AesGcmSivKey&>(
      *internal::GetAesGcmSivTestVector(32, AesGcmSivParameters::Variant::kTink)
           .aead_key);
  const AesGcmSivKey& other_key = dynamic_cast<const AesGcmSivKey&>(
      *internal::GetAesGcmSivTestVector(16,
                                        AesGcmSivParameters::Variant::kNoPrefix)
           .aead_key);

  AesGcmSivKey copy = other_key;
  copy = key;

  EXPECT_THAT(copy, Eq(key));
}

TEST(AesGcmSivKeyTest, MoveConstructor) {
  AesGcmSivKey key = dynamic_cast<const AesGcmSivKey&>(
      *internal::GetAesGcmSivTestVector(32, AesGcmSivParameters::Variant::kTink)
           .aead_key);

  AesGcmSivKey expected = key;
  AesGcmSivKey moved(std::move(key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(AesGcmSivKeyTest, MoveAssignment) {
  AesGcmSivKey key = dynamic_cast<const AesGcmSivKey&>(
      *internal::GetAesGcmSivTestVector(32, AesGcmSivParameters::Variant::kTink)
           .aead_key);
  AesGcmSivKey other_key = dynamic_cast<const AesGcmSivKey&>(
      *internal::GetAesGcmSivTestVector(16,
                                        AesGcmSivParameters::Variant::kNoPrefix)
           .aead_key);

  AesGcmSivKey expected = key;
  other_key = std::move(key);

  EXPECT_THAT(other_key, Eq(expected));
}

TEST(AesGcmSivKeyTest, Clone) {
  const AesGcmSivKey& key = dynamic_cast<const AesGcmSivKey&>(
      *internal::GetAesGcmSivTestVector(32, AesGcmSivParameters::Variant::kTink)
           .aead_key);

  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
