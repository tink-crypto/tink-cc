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

#include "tink/streamingaead/aes_ctr_hmac_streaming_key.h"

#include <memory>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"
#include "tink/streamingaead/internal/testing/aes_ctr_hmac_streaming_test_vectors.h"
#include "tink/streamingaead/internal/testing/streamingaead_test_vector.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using AesCtrHmacStreamingKeyTest =
    TestWithParam<internal::StreamingAeadTestVector>;

INSTANTIATE_TEST_SUITE_P(
    AesCtrHmacStreamingKeyTestSuite, AesCtrHmacStreamingKeyTest,
    ValuesIn(internal::CreateAesCtrHmacStreamingTestVectors()));

TEST_P(AesCtrHmacStreamingKeyTest, CreateSucceeds) {
  const internal::StreamingAeadTestVector& test_vector = GetParam();
  const AesCtrHmacStreamingKey& key =
      dynamic_cast<const AesCtrHmacStreamingKey&>(
          *test_vector.streamingaead_key);

  absl::StatusOr<AesCtrHmacStreamingKey> created_key =
      AesCtrHmacStreamingKey::Create(
          key.GetParameters(), key.GetInitialKeyMaterial(GetPartialKeyAccess()),
          GetPartialKeyAccess());
  ASSERT_THAT(created_key, IsOk());

  EXPECT_THAT(created_key->GetParameters(), Eq(key.GetParameters()));
  EXPECT_THAT(created_key->GetInitialKeyMaterial(GetPartialKeyAccess()),
              Eq(key.GetInitialKeyMaterial(GetPartialKeyAccess())));
  EXPECT_THAT(created_key->GetIdRequirement(), Eq(key.GetIdRequirement()));
}

TEST(AesCtrHmacStreamingKeyTest, CreateKeyWithMismatchedKeySizeFails) {
  const AesCtrHmacStreamingKey& key =
      dynamic_cast<const AesCtrHmacStreamingKey&>(
          *internal::GetAesCtrHmacStreamingTestVector(16).streamingaead_key);

  RestrictedData mismatched_initial_key_material =
      RestrictedData(key.GetParameters().KeySizeInBytes() + 1);

  EXPECT_THAT(AesCtrHmacStreamingKey::Create(key.GetParameters(),
                                             mismatched_initial_key_material,
                                             GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Key size does not match")));
}

TEST_P(AesCtrHmacStreamingKeyTest, KeyEquals) {
  const internal::StreamingAeadTestVector& test_vector = GetParam();
  const AesCtrHmacStreamingKey& key =
      dynamic_cast<const AesCtrHmacStreamingKey&>(
          *test_vector.streamingaead_key);

  absl::StatusOr<AesCtrHmacStreamingKey> created_key =
      AesCtrHmacStreamingKey::Create(
          key.GetParameters(), key.GetInitialKeyMaterial(GetPartialKeyAccess()),
          GetPartialKeyAccess());
  ASSERT_THAT(created_key, IsOk());

  absl::StatusOr<AesCtrHmacStreamingKey> other_key =
      AesCtrHmacStreamingKey::Create(
          key.GetParameters(), key.GetInitialKeyMaterial(GetPartialKeyAccess()),
          GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*created_key == *other_key);
  EXPECT_TRUE(*other_key == *created_key);
  EXPECT_FALSE(*created_key != *other_key);
  EXPECT_FALSE(*other_key != *created_key);
}

TEST(AesCtrHmacStreamingKeyTest, DifferentSecretDataNotEqual) {
  const AesCtrHmacStreamingKey& key1 =
      dynamic_cast<const AesCtrHmacStreamingKey&>(
          *internal::GetAesCtrHmacStreamingTestVector(16).streamingaead_key);
  const AesCtrHmacStreamingKey& key2 =
      dynamic_cast<const AesCtrHmacStreamingKey&>(
          *internal::GetAesCtrHmacStreamingTestVector(32).streamingaead_key);

  RestrictedData initial_key_material2 =
      RestrictedData(key2.GetInitialKeyMaterial(GetPartialKeyAccess())
                         .GetSecret(InsecureSecretKeyAccess::Get())
                         .substr(0, key1.GetParameters().KeySizeInBytes()),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<AesCtrHmacStreamingKey> other_key =
      AesCtrHmacStreamingKey::Create(
          key1.GetParameters(), initial_key_material2, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(key1 != *other_key);
  EXPECT_TRUE(*other_key != key1);
  EXPECT_FALSE(key1 == *other_key);
  EXPECT_FALSE(*other_key == key1);
}

TEST(AesCtrHmacStreamingKeyTest, DifferentParametersNotEqual) {
  const std::vector<internal::StreamingAeadTestVector>& test_vectors =
      internal::CreateAesCtrHmacStreamingTestVectors();
  const AesCtrHmacStreamingKey& key1 =
      dynamic_cast<const AesCtrHmacStreamingKey&>(
          *test_vectors[0].streamingaead_key);
  const AesCtrHmacStreamingKey& key2 =
      dynamic_cast<const AesCtrHmacStreamingKey&>(
          *test_vectors[2].streamingaead_key);

  EXPECT_TRUE(key1 != key2);
  EXPECT_TRUE(key2 != key1);
  EXPECT_FALSE(key1 == key2);
  EXPECT_FALSE(key2 == key1);
}

TEST(AesCtrHmacStreamingKeyTest, Clone) {
  const AesCtrHmacStreamingKey& key =
      dynamic_cast<const AesCtrHmacStreamingKey&>(
          *internal::GetAesCtrHmacStreamingTestVector(16).streamingaead_key);

  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

TEST(AesCtrHmacStreamingKeyTest, CopyConstructor) {
  const AesCtrHmacStreamingKey& key =
      dynamic_cast<const AesCtrHmacStreamingKey&>(
          *internal::GetAesCtrHmacStreamingTestVector(16).streamingaead_key);

  AesCtrHmacStreamingKey copy(key);

  EXPECT_THAT(copy, Eq(key));
}

TEST(AesCtrHmacStreamingKeyTest, CopyAssignment) {
  const AesCtrHmacStreamingKey& key1 =
      dynamic_cast<const AesCtrHmacStreamingKey&>(
          *internal::GetAesCtrHmacStreamingTestVector(16).streamingaead_key);
  const AesCtrHmacStreamingKey& key2 =
      dynamic_cast<const AesCtrHmacStreamingKey&>(
          *internal::GetAesCtrHmacStreamingTestVector(32).streamingaead_key);

  AesCtrHmacStreamingKey copy = key2;
  ASSERT_THAT(copy, Not(Eq(key1)));

  copy = key1;

  EXPECT_THAT(copy, Eq(key1));
}

TEST(AesCtrHmacStreamingKeyTest, MoveConstructor) {
  AesCtrHmacStreamingKey key = dynamic_cast<const AesCtrHmacStreamingKey&>(
      *internal::GetAesCtrHmacStreamingTestVector(16).streamingaead_key);

  AesCtrHmacStreamingKey expected = key;
  AesCtrHmacStreamingKey move(std::move(key));

  EXPECT_THAT(move, Eq(expected));
}

TEST(AesCtrHmacStreamingKeyTest, MoveAssignment) {
  AesCtrHmacStreamingKey key1 = dynamic_cast<const AesCtrHmacStreamingKey&>(
      *internal::GetAesCtrHmacStreamingTestVector(16).streamingaead_key);
  AesCtrHmacStreamingKey key2 = dynamic_cast<const AesCtrHmacStreamingKey&>(
      *internal::GetAesCtrHmacStreamingTestVector(32).streamingaead_key);

  AesCtrHmacStreamingKey expected = key1;
  key2 = std::move(key1);

  EXPECT_THAT(key2, Eq(expected));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
