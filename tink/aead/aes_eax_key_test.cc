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

#include "tink/aead/aes_eax_key.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/aes_eax_test_vectors.h"
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

using AesEaxKeyTest = TestWithParam<internal::AeadTestVector>;

INSTANTIATE_TEST_SUITE_P(AesEaxParametersBuildTestSuite, AesEaxKeyTest,
                         ValuesIn(internal::CreateAesEaxTestVectors()));

TEST_P(AesEaxKeyTest, CreateSucceeds) {
  const internal::AeadTestVector& test_vector = GetParam();
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(*test_vector.aead_key);

  absl::StatusOr<AesEaxKey> created_key = AesEaxKey::Create(
      key.GetParameters(), key.GetKeyBytes(GetPartialKeyAccess()),
      key.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(created_key, IsOk());

  EXPECT_THAT(created_key->GetParameters(), Eq(key.GetParameters()));
  EXPECT_THAT(created_key->GetIdRequirement(), Eq(key.GetIdRequirement()));
  EXPECT_THAT(created_key->GetOutputPrefix(), Eq(key.GetOutputPrefix()));
  EXPECT_THAT(created_key->GetKeyBytes(GetPartialKeyAccess()),
              Eq(key.GetKeyBytes(GetPartialKeyAccess())));
}

TEST(AesEaxKeyTest, CreateKeyWithMismatchedKeySizeFails) {
  // Key size parameter is 32 bytes.
  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  // Key material is 16 bytes (also a valid key length).
  RestrictedData mismatched_secret = RestrictedData(/*num_random_bytes=*/16);

  EXPECT_THAT(AesEaxKey::Create(*parameters, mismatched_secret,
                                /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesEaxKeyTest, CreateKeyWithInvalidIdRequirementFails) {
  absl::StatusOr<AesEaxParameters> no_prefix_parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(no_prefix_parameters, IsOk());

  absl::StatusOr<AesEaxParameters> tink_parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  // Creating a key with with ID requirement with parameters without ID
  // requirement fails */
  EXPECT_THAT(AesEaxKey::Create(*no_prefix_parameters, secret,
                                /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  // Creating a key with without ID requirement with parameters with ID
  // requirement fails */
  EXPECT_THAT(
      AesEaxKey::Create(*tink_parameters, secret,
                        /*id_requirement=*/std::nullopt, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesEaxKeyTest, KeyEquals) {
  const internal::AeadTestVector& test_vector = GetParam();
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(*test_vector.aead_key);

  absl::StatusOr<AesEaxKey> other_key = AesEaxKey::Create(
      key.GetParameters(), key.GetKeyBytes(GetPartialKeyAccess()),
      key.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(key == *other_key);
  EXPECT_TRUE(*other_key == key);
  EXPECT_FALSE(key != *other_key);
  EXPECT_FALSE(*other_key != key);
}

TEST(AesEaxKeyTest, DifferentParametersKeysNotEqual) {
  const AesEaxKey& key1 = dynamic_cast<const AesEaxKey&>(
      *internal::GetAesEaxTestVector(/*key_size_in_bytes=*/32,
                                     AesEaxParameters::Variant::kTink)
           .aead_key);
  const AesEaxKey& key2 = dynamic_cast<const AesEaxKey&>(
      *internal::GetAesEaxTestVector(/*key_size_in_bytes=*/16,
                                     AesEaxParameters::Variant::kNoPrefix)
           .aead_key);

  EXPECT_TRUE(key1 != key2);
  EXPECT_TRUE(key2 != key1);
  EXPECT_FALSE(key1 == key2);
  EXPECT_FALSE(key2 == key1);
}

TEST(AesEaxKeyTest, DifferentSecretDataKeysNotEqual) {
  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesEaxKey> key =
      AesEaxKey::Create(*parameters, secret1, /*id_requirement=*/0x01020304,
                        GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesEaxKey> other_key =
      AesEaxKey::Create(*parameters, secret2, /*id_requirement=*/0x01020304,
                        GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesEaxKeyTest, DifferentIdRequirementKeysNotEqual) {
  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesEaxKey> key =
      AesEaxKey::Create(*parameters, secret, /*id_requirement=*/0x01020304,
                        GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesEaxKey> other_key =
      AesEaxKey::Create(*parameters, secret, /*id_requirement=*/0x02030405,
                        GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesEaxKeyTest, CopyConstructor) {
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(
      *internal::GetAesEaxTestVector(/*key_size_in_bytes=*/32,
                                     AesEaxParameters::Variant::kTink)
           .aead_key);

  AesEaxKey copy(key);

  EXPECT_THAT(copy, Eq(key));
}

TEST(AesEaxKeyTest, CopyAssignment) {
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(
      *internal::GetAesEaxTestVector(/*key_size_in_bytes=*/32,
                                     AesEaxParameters::Variant::kTink)
           .aead_key);
  const AesEaxKey& other_key = dynamic_cast<const AesEaxKey&>(
      *internal::GetAesEaxTestVector(/*key_size_in_bytes=*/16,
                                     AesEaxParameters::Variant::kNoPrefix)
           .aead_key);

  AesEaxKey copy = other_key;
  copy = key;

  EXPECT_THAT(copy, Eq(key));
}

TEST(AesEaxKeyTest, MoveConstructor) {
  AesEaxKey key = dynamic_cast<const AesEaxKey&>(
      *internal::GetAesEaxTestVector(/*key_size_in_bytes=*/32,
                                     AesEaxParameters::Variant::kTink)
           .aead_key);

  AesEaxKey expected = key;
  AesEaxKey move(std::move(key));

  EXPECT_THAT(move, Eq(expected));
}

TEST(AesEaxKeyTest, MoveAssignment) {
  AesEaxKey key = dynamic_cast<const AesEaxKey&>(
      *internal::GetAesEaxTestVector(/*key_size_in_bytes=*/32,
                                     AesEaxParameters::Variant::kTink)
           .aead_key);
  AesEaxKey other_key = dynamic_cast<const AesEaxKey&>(
      *internal::GetAesEaxTestVector(/*key_size_in_bytes=*/16,
                                     AesEaxParameters::Variant::kNoPrefix)
           .aead_key);

  AesEaxKey expected = key;
  other_key = std::move(key);

  EXPECT_THAT(other_key, Eq(expected));
}

TEST(AesEaxKeyTest, Clone) {
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(
      *internal::GetAesEaxTestVector(/*key_size_in_bytes=*/32,
                                     AesEaxParameters::Variant::kTink)
           .aead_key);

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
