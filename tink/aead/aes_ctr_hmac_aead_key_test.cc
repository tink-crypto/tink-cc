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

#include "tink/aead/aes_ctr_hmac_aead_key.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/aes_ctr_hmac_aead_test_vectors.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using AesCtrHmacAeadKeyTest = TestWithParam<internal::AeadTestVector>;

INSTANTIATE_TEST_SUITE_P(AesCtrHmacAeadKeyBuildTestSuite, AesCtrHmacAeadKeyTest,
                         ValuesIn(internal::CreateAesCtrHmacAeadTestVectors()));

TEST_P(AesCtrHmacAeadKeyTest, BuildKeySucceeds) {
  const internal::AeadTestVector& test_vector = GetParam();
  const AesCtrHmacAeadKey& key =
      dynamic_cast<const AesCtrHmacAeadKey&>(*test_vector.aead_key);

  absl::StatusOr<AesCtrHmacAeadKey> created_key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(key.GetParameters())
          .SetAesKeyBytes(key.GetAesKeyBytes(GetPartialKeyAccess()))
          .SetHmacKeyBytes(key.GetHmacKeyBytes(GetPartialKeyAccess()))
          .SetIdRequirement(key.GetIdRequirement())
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(created_key, IsOk());

  EXPECT_THAT(created_key->GetParameters(), Eq(key.GetParameters()));
  EXPECT_THAT(created_key->GetIdRequirement(), Eq(key.GetIdRequirement()));
  EXPECT_THAT(created_key->GetOutputPrefix(), Eq(key.GetOutputPrefix()));
  EXPECT_THAT(created_key->GetAesKeyBytes(GetPartialKeyAccess()),
              Eq(key.GetAesKeyBytes(GetPartialKeyAccess())));
  EXPECT_THAT(created_key->GetHmacKeyBytes(GetPartialKeyAccess()),
              Eq(key.GetHmacKeyBytes(GetPartialKeyAccess())));
}

TEST(AesCtrHmacAeadKeyTest, BuildKeyWithMismatchedAesKeySizeFails) {
  // AES key size parameter is 32 bytes.
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  // AES key material size is 16 bytes (also a valid key length).
  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/16);
  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(AesCtrHmacAeadKey::Builder()
                  .SetParameters(*parameters)
                  .SetAesKeyBytes(aes_secret)
                  .SetHmacKeyBytes(hmac_secret)
                  .SetIdRequirement(123)
                  .Build(GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("AES key size does not match")));
}

TEST(AesCtrHmacAeadKeyTest, BuildKeyWithoutSettingAParametersFails) {
  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(
      AesCtrHmacAeadKey::Builder()
          .SetAesKeyBytes(aes_secret)
          .SetHmacKeyBytes(hmac_secret)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Cannot build without setting the parameters")));
}

TEST(AesCtrHmacAeadKeyTest, BuildKeyWithoutSettingAesKeySizeFails) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(AesCtrHmacAeadKey::Builder()
                  .SetParameters(*parameters)
                  .SetHmacKeyBytes(hmac_secret)
                  .SetIdRequirement(123)
                  .Build(GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot build without AES key material")));
}

TEST(AesCtrHmacAeadKeyTest, BuildKeyWithoutSettingHmacKeySizeFails) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(AesCtrHmacAeadKey::Builder()
                  .SetParameters(*parameters)
                  .SetAesKeyBytes(aes_secret)
                  .SetIdRequirement(123)
                  .Build(GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot build without HMAC key material")));
}

TEST(AesCtrHmacAeadKeyTest, BuildKeyWithMismatchedHmacKeySizeFails) {
  // HMAC key size parameter is 32 bytes.
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  // HMAC key material size is 16 bytes (also a valid key length).
  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/16);

  EXPECT_THAT(AesCtrHmacAeadKey::Builder()
                  .SetParameters(*parameters)
                  .SetAesKeyBytes(aes_secret)
                  .SetHmacKeyBytes(hmac_secret)
                  .SetIdRequirement(123)
                  .Build(GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("HMAC key size does not match")));
}

TEST(AesCtrHmacAeadKeyTest, BuildNoPrefixKeyWithIdRequirementFails) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(AesCtrHmacAeadKey::Builder()
                  .SetParameters(*parameters)
                  .SetAesKeyBytes(aes_secret)
                  .SetHmacKeyBytes(hmac_secret)
                  .SetIdRequirement(123)
                  .Build(GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement with "
                                 "parameters without ID requirement")));
}

TEST(AesCtrHmacAeadKeyTest, BuildTinkKeyWithoutIdRequirementFails) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(AesCtrHmacAeadKey::Builder()
                  .SetParameters(*parameters)
                  .SetAesKeyBytes(aes_secret)
                  .SetHmacKeyBytes(hmac_secret)
                  .Build(GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key without ID requirement "
                                 "with parameters with ID requirement")));
}

TEST_P(AesCtrHmacAeadKeyTest, KeyEquals) {
  const internal::AeadTestVector& test_vector = GetParam();
  const AesCtrHmacAeadKey& key =
      dynamic_cast<const AesCtrHmacAeadKey&>(*test_vector.aead_key);

  absl::StatusOr<AesCtrHmacAeadKey> created_key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(key.GetParameters())
          .SetAesKeyBytes(key.GetAesKeyBytes(GetPartialKeyAccess()))
          .SetHmacKeyBytes(key.GetHmacKeyBytes(GetPartialKeyAccess()))
          .SetIdRequirement(key.GetIdRequirement())
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(created_key, IsOk());

  absl::StatusOr<AesCtrHmacAeadKey> other_key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(key.GetParameters())
          .SetAesKeyBytes(key.GetAesKeyBytes(GetPartialKeyAccess()))
          .SetHmacKeyBytes(key.GetHmacKeyBytes(GetPartialKeyAccess()))
          .SetIdRequirement(key.GetIdRequirement())
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*created_key == *other_key);
  EXPECT_TRUE(*other_key == *created_key);
  EXPECT_FALSE(*created_key != *other_key);
  EXPECT_FALSE(*other_key != *created_key);
}

TEST(AesCtrHmacAeadKeyTest, DifferentParametersKeysNotEqual) {
  const AesCtrHmacAeadKey& key1 = dynamic_cast<const AesCtrHmacAeadKey&>(
      *internal::GetAesCtrHmacAeadTestVector(
           /*aes_key_size_in_bytes=*/32,
           AesCtrHmacAeadParameters::Variant::kTink)
           .aead_key);
  const AesCtrHmacAeadKey& key2 = dynamic_cast<const AesCtrHmacAeadKey&>(
      *internal::GetAesCtrHmacAeadTestVector(
           /*aes_key_size_in_bytes=*/16,
           AesCtrHmacAeadParameters::Variant::kNoPrefix)
           .aead_key);

  EXPECT_TRUE(key1 != key2);
  EXPECT_TRUE(key2 != key1);
  EXPECT_FALSE(key1 == key2);
  EXPECT_FALSE(key2 == key1);
}

TEST(AesCtrHmacAeadKeyTest, DifferentAesKeyMaterialNotEqual) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData aes_secret1 = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData aes_secret2 = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesCtrHmacAeadKey> key = AesCtrHmacAeadKey::Builder()
                                              .SetParameters(*parameters)
                                              .SetAesKeyBytes(aes_secret1)
                                              .SetHmacKeyBytes(hmac_secret)
                                              .SetIdRequirement(0x01020304)
                                              .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesCtrHmacAeadKey> other_key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*parameters)
          .SetAesKeyBytes(aes_secret2)
          .SetHmacKeyBytes(hmac_secret)
          .SetIdRequirement(0x01020304)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesCtrHmacAeadKeyTest, DifferentHmacKeyMaterialNotEqual) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret1 = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret2 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesCtrHmacAeadKey> key = AesCtrHmacAeadKey::Builder()
                                              .SetParameters(*parameters)
                                              .SetAesKeyBytes(aes_secret)
                                              .SetHmacKeyBytes(hmac_secret1)
                                              .SetIdRequirement(0x01020304)
                                              .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesCtrHmacAeadKey> other_key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*parameters)
          .SetAesKeyBytes(aes_secret)
          .SetHmacKeyBytes(hmac_secret2)
          .SetIdRequirement(0x01020304)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesCtrHmacAeadKeyTest, DifferentIdRequirementKeysNotEqual) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(32)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData aes_secret = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData hmac_secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesCtrHmacAeadKey> key = AesCtrHmacAeadKey::Builder()
                                              .SetParameters(*parameters)
                                              .SetAesKeyBytes(aes_secret)
                                              .SetHmacKeyBytes(hmac_secret)
                                              .SetIdRequirement(0x01020304)
                                              .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesCtrHmacAeadKey> other_key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*parameters)
          .SetAesKeyBytes(aes_secret)
          .SetHmacKeyBytes(hmac_secret)
          .SetIdRequirement(0x02030405)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesCtrHmacAeadKeyTest, CopyConstructor) {
  const auto& key = dynamic_cast<const AesCtrHmacAeadKey&>(
      *internal::GetAesCtrHmacAeadTestVector(
           /*aes_key_size_in_bytes=*/16,
           AesCtrHmacAeadParameters::Variant::kTink)
           .aead_key);

  AesCtrHmacAeadKey copy(key);

  EXPECT_THAT(copy, Eq(key));
}

TEST(AesCtrHmacAeadKeyTest, CopyAssignment) {
  const auto& key = dynamic_cast<const AesCtrHmacAeadKey&>(
      *internal::GetAesCtrHmacAeadTestVector(
           /*aes_key_size_in_bytes=*/16,
           AesCtrHmacAeadParameters::Variant::kTink)
           .aead_key);
  const auto& other_key = dynamic_cast<const AesCtrHmacAeadKey&>(
      *internal::GetAesCtrHmacAeadTestVector(
           /*aes_key_size_in_bytes=*/32,
           AesCtrHmacAeadParameters::Variant::kNoPrefix)
           .aead_key);

  AesCtrHmacAeadKey copy = other_key;
  copy = key;

  EXPECT_THAT(copy, Eq(key));
}

TEST(AesCtrHmacAeadKeyTest, MoveConstructor) {
  AesCtrHmacAeadKey key = dynamic_cast<const AesCtrHmacAeadKey&>(
      *internal::GetAesCtrHmacAeadTestVector(
           /*aes_key_size_in_bytes=*/16,
           AesCtrHmacAeadParameters::Variant::kTink)
           .aead_key);

  AesCtrHmacAeadKey expected = key;
  AesCtrHmacAeadKey move(std::move(key));

  EXPECT_THAT(move, Eq(expected));
}

TEST(AesCtrHmacAeadKeyTest, MoveAssignment) {
  AesCtrHmacAeadKey key = dynamic_cast<const AesCtrHmacAeadKey&>(
      *internal::GetAesCtrHmacAeadTestVector(
           /*aes_key_size_in_bytes=*/16,
           AesCtrHmacAeadParameters::Variant::kTink)
           .aead_key);
  AesCtrHmacAeadKey other_key = dynamic_cast<const AesCtrHmacAeadKey&>(
      *internal::GetAesCtrHmacAeadTestVector(
           /*aes_key_size_in_bytes=*/32,
           AesCtrHmacAeadParameters::Variant::kNoPrefix)
           .aead_key);

  AesCtrHmacAeadKey expected = key;
  other_key = std::move(key);

  EXPECT_THAT(other_key, Eq(expected));
}

TEST(AesCtrHmacAeadKeyTest, Clone) {
  const auto& key = dynamic_cast<const AesCtrHmacAeadKey&>(
      *internal::GetAesCtrHmacAeadTestVector(
           /*aes_key_size_in_bytes=*/16,
           AesCtrHmacAeadParameters::Variant::kTink)
           .aead_key);

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
