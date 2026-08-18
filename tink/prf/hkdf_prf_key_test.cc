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

#include "tink/prf/hkdf_prf_key.h"

#include <memory>
#include <optional>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/prf/internal/hkdf_prf_test_vectors.h"
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

using HkdfPrfKeyTest = TestWithParam<internal::HkdfPrfTestVector>;

INSTANTIATE_TEST_SUITE_P(HkdfPrfKeyTestSuite, HkdfPrfKeyTest,
                         ValuesIn(internal::CreateHkdfPrfTestVectors()));

TEST_P(HkdfPrfKeyTest, CreateSucceeds) {
  const internal::HkdfPrfTestVector& test_vector = GetParam();

  RestrictedData secret = test_vector.key.GetKeyBytes(GetPartialKeyAccess());
  absl::StatusOr<HkdfPrfKey> key = HkdfPrfKey::Create(
      test_vector.key.GetParameters(), secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(key->GetParameters(), Eq(test_vector.key.GetParameters()));
  EXPECT_THAT(key->GetIdRequirement(), Eq(std::nullopt));
}

TEST(HkdfPrfKeyTest, CreateKeyWithNonMatchingKeySizeFails) {
  const internal::HkdfPrfTestVector& test_vector22 =
      internal::GetHkdfPrfTestVector(22, HkdfPrfParameters::HashType::kSha256);
  const internal::HkdfPrfTestVector& test_vector80 =
      internal::GetHkdfPrfTestVector(80, HkdfPrfParameters::HashType::kSha256);

  EXPECT_THAT(
      HkdfPrfKey::Create(test_vector22.key.GetParameters(),
                         test_vector80.key.GetKeyBytes(GetPartialKeyAccess()),
                         GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Key size does not match HKDF-PRF parameters")));
}

TEST_P(HkdfPrfKeyTest, KeyEquals) {
  const internal::HkdfPrfTestVector& test_vector = GetParam();

  HkdfPrfKey copy = test_vector.key;

  EXPECT_TRUE(test_vector.key == copy);
  EXPECT_TRUE(copy == test_vector.key);
  EXPECT_FALSE(test_vector.key != copy);
  EXPECT_FALSE(copy != test_vector.key);
}

TEST(HkdfPrfKeyTest, DifferentSecretDataNotEqual) {
  const internal::HkdfPrfTestVector& test_vector =
      internal::GetHkdfPrfTestVector(22, HkdfPrfParameters::HashType::kSha256);

  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/22);

  absl::StatusOr<HkdfPrfKey> other_key = HkdfPrfKey::Create(
      test_vector.key.GetParameters(), secret2, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(test_vector.key != *other_key);
  EXPECT_TRUE(*other_key != test_vector.key);
  EXPECT_FALSE(test_vector.key == *other_key);
  EXPECT_FALSE(*other_key == test_vector.key);
}

TEST(HkdfPrfKeyTest, DifferentParametersNotEqual) {
  const HkdfPrfKey& key1 =
      internal::GetHkdfPrfTestVector(22, HkdfPrfParameters::HashType::kSha256)
          .key;
  const HkdfPrfKey& key2 =
      internal::GetHkdfPrfTestVector(80, HkdfPrfParameters::HashType::kSha256)
          .key;

  EXPECT_TRUE(key1 != key2);
  EXPECT_TRUE(key2 != key1);
  EXPECT_FALSE(key1 == key2);
  EXPECT_FALSE(key2 == key1);
}

TEST(HkdfPrfKeyTest, CopyConstructor) {
  const HkdfPrfKey& key =
      internal::GetHkdfPrfTestVector(22, HkdfPrfParameters::HashType::kSha256)
          .key;

  HkdfPrfKey copy(key);

  EXPECT_THAT(copy, Eq(key));
}

TEST(HkdfPrfKeyTest, CopyAssignment) {
  const HkdfPrfKey& key =
      internal::GetHkdfPrfTestVector(22, HkdfPrfParameters::HashType::kSha256)
          .key;
  const HkdfPrfKey& other_key =
      internal::GetHkdfPrfTestVector(80, HkdfPrfParameters::HashType::kSha256)
          .key;

  HkdfPrfKey copy = other_key;
  copy = key;

  EXPECT_THAT(copy, Eq(key));
}

TEST(HkdfPrfKeyTest, MoveConstructor) {
  HkdfPrfKey key =
      internal::GetHkdfPrfTestVector(22, HkdfPrfParameters::HashType::kSha256)
          .key;

  HkdfPrfKey expected = key;
  HkdfPrfKey moved(std::move(key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(HkdfPrfKeyTest, MoveAssignment) {
  HkdfPrfKey key =
      internal::GetHkdfPrfTestVector(22, HkdfPrfParameters::HashType::kSha256)
          .key;
  HkdfPrfKey other_key =
      internal::GetHkdfPrfTestVector(80, HkdfPrfParameters::HashType::kSha256)
          .key;

  HkdfPrfKey expected = key;
  other_key = std::move(key);

  EXPECT_THAT(other_key, Eq(expected));
}

TEST(HkdfPrfKeyTest, Clone) {
  const HkdfPrfKey& key =
      internal::GetHkdfPrfTestVector(22, HkdfPrfParameters::HashType::kSha256)
          .key;

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
