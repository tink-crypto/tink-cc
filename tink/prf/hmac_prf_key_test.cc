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

#include "tink/prf/hmac_prf_key.h"

#include <memory>
#include <optional>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/prf/internal/hmac_prf_test_vectors.h"
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

using HmacPrfKeyTest = TestWithParam<internal::HmacPrfTestVector>;

INSTANTIATE_TEST_SUITE_P(HmacPrfKeyTestSuite, HmacPrfKeyTest,
                         ValuesIn(internal::CreateHmacPrfTestVectors()));

TEST_P(HmacPrfKeyTest, CreateSucceeds) {
  const internal::HmacPrfTestVector& test_vector = GetParam();

  RestrictedData secret = test_vector.key.GetKeyBytes(GetPartialKeyAccess());
  absl::StatusOr<HmacPrfKey> key = HmacPrfKey::Create(
      test_vector.key.GetParameters(), secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(key->GetParameters(), Eq(test_vector.key.GetParameters()));
  EXPECT_THAT(key->GetIdRequirement(), Eq(std::nullopt));
}

TEST(HmacPrfKeyTest, CreateKeyWithNonMatchingKeySizeFails) {
  const internal::HmacPrfTestVector& test_vector32 =
      internal::GetHmacPrfTestVector(32, HmacPrfParameters::HashType::kSha1);
  const internal::HmacPrfTestVector& test_vector40 =
      internal::GetHmacPrfTestVector(40, HmacPrfParameters::HashType::kSha256);

  EXPECT_THAT(
      HmacPrfKey::Create(test_vector32.key.GetParameters(),
                         test_vector40.key.GetKeyBytes(GetPartialKeyAccess()),
                         GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Key size does not match HMAC-PRF parameters")));
}

TEST_P(HmacPrfKeyTest, KeyEquals) {
  const internal::HmacPrfTestVector& test_vector = GetParam();

  HmacPrfKey copy = test_vector.key;

  EXPECT_TRUE(test_vector.key == copy);
  EXPECT_TRUE(copy == test_vector.key);
  EXPECT_FALSE(test_vector.key != copy);
  EXPECT_FALSE(copy != test_vector.key);
}

TEST(HmacPrfKeyTest, DifferentSecretDataNotEqual) {
  const internal::HmacPrfTestVector& test_vector =
      internal::GetHmacPrfTestVector(32, HmacPrfParameters::HashType::kSha1);

  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<HmacPrfKey> other_key = HmacPrfKey::Create(
      test_vector.key.GetParameters(), secret2, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(test_vector.key != *other_key);
  EXPECT_TRUE(*other_key != test_vector.key);
  EXPECT_FALSE(test_vector.key == *other_key);
  EXPECT_FALSE(*other_key == test_vector.key);
}

TEST(HmacPrfKeyTest, DifferentParametersNotEqual) {
  const HmacPrfKey& key1 =
      internal::GetHmacPrfTestVector(32, HmacPrfParameters::HashType::kSha1)
          .key;
  const HmacPrfKey& key2 =
      internal::GetHmacPrfTestVector(40, HmacPrfParameters::HashType::kSha256)
          .key;

  EXPECT_TRUE(key1 != key2);
  EXPECT_TRUE(key2 != key1);
  EXPECT_FALSE(key1 == key2);
  EXPECT_FALSE(key2 == key1);
}

TEST(HmacPrfKeyTest, Clone) {
  const HmacPrfKey& key =
      internal::GetHmacPrfTestVector(32, HmacPrfParameters::HashType::kSha1)
          .key;

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

TEST(HmacPrfKeyTest, CopyConstructor) {
  const HmacPrfKey& key =
      internal::GetHmacPrfTestVector(32, HmacPrfParameters::HashType::kSha1)
          .key;

  HmacPrfKey copy(key);

  EXPECT_THAT(copy, Eq(key));
}

TEST(HmacPrfKeyTest, CopyAssignment) {
  const HmacPrfKey& key =
      internal::GetHmacPrfTestVector(32, HmacPrfParameters::HashType::kSha1)
          .key;
  const HmacPrfKey& other_key =
      internal::GetHmacPrfTestVector(40, HmacPrfParameters::HashType::kSha256)
          .key;

  HmacPrfKey copy = other_key;
  copy = key;

  EXPECT_THAT(copy, Eq(key));
}

TEST(HmacPrfKeyTest, MoveConstructor) {
  HmacPrfKey key =
      internal::GetHmacPrfTestVector(32, HmacPrfParameters::HashType::kSha1)
          .key;

  HmacPrfKey expected = key;
  HmacPrfKey moved(std::move(key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(HmacPrfKeyTest, MoveAssignment) {
  HmacPrfKey key =
      internal::GetHmacPrfTestVector(32, HmacPrfParameters::HashType::kSha1)
          .key;
  HmacPrfKey other_key =
      internal::GetHmacPrfTestVector(40, HmacPrfParameters::HashType::kSha256)
          .key;

  HmacPrfKey expected = key;
  other_key = std::move(key);

  EXPECT_THAT(other_key, Eq(expected));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
