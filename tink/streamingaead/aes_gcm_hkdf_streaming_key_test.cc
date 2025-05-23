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

#include "tink/streamingaead/aes_gcm_hkdf_streaming_key.h"

#include <memory>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;

TEST(AesGcmHkdfStreamingKeyTest, CreateSucceeds) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData initial_key_material =
      RestrictedData(parameters->KeySizeInBytes());
  absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
      *parameters, initial_key_material, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetInitialKeyMaterial(GetPartialKeyAccess()),
              Eq(initial_key_material));
  EXPECT_THAT(key->GetIdRequirement(), Eq(absl::nullopt));
}

TEST(AesGcmHkdfStreamingKeyTest, CreateKeyWithMismatchedKeySizeFails) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  // Key material is 36 bytes (another valid key length).
  RestrictedData mismatched_initial_key_material =
      RestrictedData(parameters->KeySizeInBytes() + 1);

  EXPECT_THAT(
      AesGcmHkdfStreamingKey::Create(
          *parameters, mismatched_initial_key_material, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Key size does not match")));
}

TEST(AesGcmHkdfStreamingKeyTest, KeyEquals) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData initial_key_material =
      RestrictedData(parameters->KeySizeInBytes());

  absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
      *parameters, initial_key_material, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesGcmHkdfStreamingKey> other_key =
      AesGcmHkdfStreamingKey::Create(*parameters, initial_key_material,
                                     GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(AesGcmHkdfStreamingKeyTest, DifferentSecretDataNotEqual) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData initial_key_material1 =
      RestrictedData(parameters->KeySizeInBytes());
  RestrictedData initial_key_material2 =
      RestrictedData(parameters->KeySizeInBytes());

  absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
      *parameters, initial_key_material1, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesGcmHkdfStreamingKey> other_key =
      AesGcmHkdfStreamingKey::Create(*parameters, initial_key_material2,
                                     GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesGcmHkdfStreamingKeyTest, DifferentParametersNotEqual) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters1 =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters1, IsOk());

  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters2 =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters2, IsOk());

  RestrictedData initial_key_material =
      RestrictedData(parameters1->KeySizeInBytes());

  absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
      *parameters1, initial_key_material, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesGcmHkdfStreamingKey> other_key =
      AesGcmHkdfStreamingKey::Create(*parameters2, initial_key_material,
                                     GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesGcmHkdfStreamingKeyTest, Clone) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData initial_key_material =
      RestrictedData(parameters->KeySizeInBytes());

  absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
      *parameters, initial_key_material, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*key));
}

TEST(AesGcmHkdfStreamingKeyTest, CopyConstructor) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData initial_key_material =
      RestrictedData(parameters->KeySizeInBytes());

  absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
      *parameters, initial_key_material, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  AesGcmHkdfStreamingKey copy(*key);

  EXPECT_THAT(copy, Eq(*key));
}

TEST(AesGcmHkdfStreamingKeyTest, CopyAssignment) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData initial_key_material =
      RestrictedData(parameters->KeySizeInBytes());
  RestrictedData other_initial_key_material =
      RestrictedData(parameters->KeySizeInBytes());

  absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
      *parameters, initial_key_material, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesGcmHkdfStreamingKey> copy = AesGcmHkdfStreamingKey::Create(
      *parameters, other_initial_key_material, GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());
  ASSERT_THAT(copy, Not(Eq(key)));

  *copy = *key;

  EXPECT_THAT(*copy, Eq(*key));
}

TEST(AesGcmHkdfStreamingKeyTest, MoveConstructor) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData initial_key_material =
      RestrictedData(parameters->KeySizeInBytes());

  absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
      *parameters, initial_key_material, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  AesGcmHkdfStreamingKey move(std::move(*key));

  EXPECT_THAT(move.GetParameters(), Eq(*parameters));
  EXPECT_THAT(move.GetInitialKeyMaterial(GetPartialKeyAccess()),
              Eq(initial_key_material));
}

TEST(AesGcmHkdfStreamingKeyTest, MoveAssignment) {
  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(35)
          .SetDerivedKeySizeInBytes(32)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha512)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData initial_key_material =
      RestrictedData(parameters->KeySizeInBytes());
  RestrictedData other_initial_key_material =
      RestrictedData(parameters->KeySizeInBytes());

  absl::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
      *parameters, initial_key_material, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesGcmHkdfStreamingKey> move = AesGcmHkdfStreamingKey::Create(
      *parameters, other_initial_key_material, GetPartialKeyAccess());
  ASSERT_THAT(move, IsOk());
  ASSERT_THAT(move, Not(Eq(key)));

  *move = std::move(*key);

  EXPECT_THAT(move->GetInitialKeyMaterial(GetPartialKeyAccess()),
              Eq(initial_key_material));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
