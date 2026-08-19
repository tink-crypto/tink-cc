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

#include "tink/prf/aes_cmac_prf_key.h"

#include <memory>
#include <optional>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/prf/internal/aes_cmac_prf_test_vectors.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using AesCmacPrfKeyTest = TestWithParam<internal::AesCmacPrfTestVector>;

INSTANTIATE_TEST_SUITE_P(AesCmacPrfKeyTestSuite, AesCmacPrfKeyTest,
                         ValuesIn(internal::CreateAesCmacPrfTestVectors()));

TEST_P(AesCmacPrfKeyTest, CreateSucceeds) {
  const internal::AesCmacPrfTestVector& test_vector = GetParam();

  RestrictedData secret = test_vector.key.GetKeyBytes(GetPartialKeyAccess());
  absl::StatusOr<AesCmacPrfKey> key =
      AesCmacPrfKey::Create(secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(key->GetParameters(), Eq(test_vector.key.GetParameters()));
  EXPECT_THAT(key->GetIdRequirement(), Eq(std::nullopt));
}

TEST(AesCmacPrfKeyTest, CreateKeyWithInvalidKeySizeFails) {
  EXPECT_THAT(AesCmacPrfKey::Create(RestrictedData(/*num_random_bytes=*/17),
                                    GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(AesCmacPrfKey::Create(RestrictedData(/*num_random_bytes=*/33),
                                    GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesCmacPrfKeyTest, KeyEquals) {
  const internal::AesCmacPrfTestVector& test_vector = GetParam();

  AesCmacPrfKey copy = test_vector.key;

  EXPECT_TRUE(test_vector.key == copy);
  EXPECT_TRUE(copy == test_vector.key);
  EXPECT_FALSE(test_vector.key != copy);
  EXPECT_FALSE(copy != test_vector.key);
}

TEST(AesCmacPrfKeyTest, DifferentSecretDataNotEqual) {
  const internal::AesCmacPrfTestVector& test_vector =
      internal::GetAesCmacPrfTestVector(16);

  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/16);

  absl::StatusOr<AesCmacPrfKey> other_key =
      AesCmacPrfKey::Create(secret2, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(test_vector.key != *other_key);
  EXPECT_TRUE(*other_key != test_vector.key);
  EXPECT_FALSE(test_vector.key == *other_key);
  EXPECT_FALSE(*other_key == test_vector.key);
}

TEST(AesCmacPrfKeyTest, DifferentParametersNotEqual) {
  const AesCmacPrfKey& key1 = internal::GetAesCmacPrfTestVector(16).key;
  const AesCmacPrfKey& key2 = internal::GetAesCmacPrfTestVector(32).key;

  EXPECT_TRUE(key1 != key2);
  EXPECT_TRUE(key2 != key1);
  EXPECT_FALSE(key1 == key2);
  EXPECT_FALSE(key2 == key1);
}

TEST(AesCmacPrfKeyTest, CopyConstructor) {
  const AesCmacPrfKey& key = internal::GetAesCmacPrfTestVector(16).key;

  AesCmacPrfKey copy(key);

  EXPECT_THAT(copy, Eq(key));
}

TEST(AesCmacPrfKeyTest, CopyAssignment) {
  const AesCmacPrfKey& key = internal::GetAesCmacPrfTestVector(16).key;
  const AesCmacPrfKey& other_key = internal::GetAesCmacPrfTestVector(32).key;

  AesCmacPrfKey copy = other_key;
  copy = key;

  EXPECT_THAT(copy, Eq(key));
}

TEST(AesCmacPrfKeyTest, MoveConstructor) {
  AesCmacPrfKey key = internal::GetAesCmacPrfTestVector(16).key;

  AesCmacPrfKey expected = key;
  AesCmacPrfKey moved(std::move(key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(AesCmacPrfKeyTest, MoveAssignment) {
  AesCmacPrfKey key = internal::GetAesCmacPrfTestVector(16).key;
  AesCmacPrfKey other_key = internal::GetAesCmacPrfTestVector(32).key;

  AesCmacPrfKey expected = key;
  other_key = std::move(key);

  EXPECT_THAT(other_key, Eq(expected));
}

TEST(AesCmacPrfKeyTest, Clone) {
  const AesCmacPrfKey& key = internal::GetAesCmacPrfTestVector(16).key;

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
