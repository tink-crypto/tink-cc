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
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::Values;

using AesCmacPrfKeyTest = TestWithParam<int>;

INSTANTIATE_TEST_SUITE_P(AesCmacPrfKeyTestSuite, AesCmacPrfKeyTest,
                         Values(16, 32));

TEST_P(AesCmacPrfKeyTest, CreateSucceeds) {
  int key_size = GetParam();

  RestrictedData secret = RestrictedData(key_size);
  absl::StatusOr<AesCmacPrfKey> key =
      AesCmacPrfKey::Create(secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesCmacPrfParameters> expected_parameters =
      AesCmacPrfParameters::Create(key_size);
  ASSERT_THAT(expected_parameters, IsOk());

  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(key->GetParameters(), Eq(*expected_parameters));
  EXPECT_THAT(key->GetIdRequirement(), Eq(absl::nullopt));
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
  int key_size = GetParam();

  RestrictedData secret = RestrictedData(key_size);
  absl::StatusOr<AesCmacPrfKey> key =
      AesCmacPrfKey::Create(secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesCmacPrfKey> other_key =
      AesCmacPrfKey::Create(secret, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(AesCmacPrfKeyTest, DifferentSecretDataNotEqual) {
  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/16);
  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/16);

  absl::StatusOr<AesCmacPrfKey> key =
      AesCmacPrfKey::Create(secret1, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesCmacPrfKey> other_key =
      AesCmacPrfKey::Create(secret2, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(AesCmacPrfKeyTest, CopyConstructor) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/16);
  absl::StatusOr<AesCmacPrfKey> key =
      AesCmacPrfKey::Create(secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  AesCmacPrfKey copy(*key);

  EXPECT_THAT(copy.GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(copy.GetParameters(), Eq(key->GetParameters()));
}

TEST(AesCmacPrfKeyTest, CopyAssignment) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/16);
  absl::StatusOr<AesCmacPrfKey> key =
      AesCmacPrfKey::Create(secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  RestrictedData other_secret = RestrictedData(/*num_random_bytes=*/32);
  absl::StatusOr<AesCmacPrfKey> other_key =
      AesCmacPrfKey::Create(other_secret, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  *other_key = *key;

  EXPECT_THAT(other_key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(other_key->GetParameters(), Eq(key->GetParameters()));
}

TEST(AesCmacPrfKeyTest, MoveConstructor) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/16);
  absl::StatusOr<AesCmacPrfKey> key =
      AesCmacPrfKey::Create(secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  AesCmacPrfParameters parameters = key->GetParameters();
  AesCmacPrfKey moved_key(std::move(*key));

  EXPECT_THAT(moved_key.GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(moved_key.GetParameters(), Eq(parameters));
}

TEST(AesCmacPrfKeyTest, MoveAssignment) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/16);
  absl::StatusOr<AesCmacPrfKey> key =
      AesCmacPrfKey::Create(secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  RestrictedData other_secret = RestrictedData(/*num_random_bytes=*/32);
  absl::StatusOr<AesCmacPrfKey> other_key =
      AesCmacPrfKey::Create(other_secret, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  AesCmacPrfParameters parameters = key->GetParameters();
  *other_key = std::move(*key);

  EXPECT_THAT(other_key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(other_key->GetParameters(), Eq(parameters));
}

TEST(AesCmacPrfKeyTest, Clone) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/16);

  absl::StatusOr<AesCmacPrfKey> key =
      AesCmacPrfKey::Create(secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
