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
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  int key_size;
  HmacPrfParameters::HashType hash_type;
};

using HmacPrfKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    HmacPrfKeyCreateTestSuite, HmacPrfKeyTest,
    Values(TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha1},
           TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha224},
           TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha256},
           TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha384},
           TestCase{/*key_size=*/32, HmacPrfParameters::HashType::kSha512}));

TEST_P(HmacPrfKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<HmacPrfParameters> parameters =
      HmacPrfParameters::Create(test_case.key_size, test_case.hash_type);
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret = RestrictedData(test_case.key_size);
  absl::StatusOr<HmacPrfKey> key =
      HmacPrfKey::Create(*parameters, secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement(), Eq(absl::nullopt));
}

TEST(HmacPrfKeyTest, CreateKeyWithNonMatchingKeySizeFails) {
  absl::StatusOr<HmacPrfParameters> parameters =
      HmacPrfParameters::Create(16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(
      HmacPrfKey::Create(*parameters, RestrictedData(/*num_random_bytes=*/32),
                         GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Key size does not match HMAC-PRF parameters")));
}

TEST_P(HmacPrfKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<HmacPrfParameters> parameters =
      HmacPrfParameters::Create(test_case.key_size, test_case.hash_type);
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret = RestrictedData(test_case.key_size);
  absl::StatusOr<HmacPrfKey> key =
      HmacPrfKey::Create(*parameters, secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<HmacPrfKey> other_key =
      HmacPrfKey::Create(*parameters, secret, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(HmacPrfKeyTest, DifferentSecretDataNotEqual) {
  absl::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/16);
  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/16);

  absl::StatusOr<HmacPrfKey> key =
      HmacPrfKey::Create(*parameters, secret1, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<HmacPrfKey> other_key =
      HmacPrfKey::Create(*parameters, secret2, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(HmacPrfKeyTest, DifferentParametersNotEqual) {
  absl::StatusOr<HmacPrfParameters> parameters1 = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters1, IsOk());

  absl::StatusOr<HmacPrfParameters> parameters2 = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha384);
  ASSERT_THAT(parameters2, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/16);

  absl::StatusOr<HmacPrfKey> key =
      HmacPrfKey::Create(*parameters1, secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<HmacPrfKey> other_key =
      HmacPrfKey::Create(*parameters2, secret, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(HmacPrfKeyTest, Clone) {
  absl::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/16);

  absl::StatusOr<HmacPrfKey> key =
      HmacPrfKey::Create(*parameters, secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*key));
}

TEST(HmacPrfKeyTest, CopyConstructor) {
  absl::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/16);
  absl::StatusOr<HmacPrfKey> key =
      HmacPrfKey::Create(*parameters, secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  HmacPrfKey copy(*key);

  EXPECT_THAT(copy, Eq(*key));
}

TEST(HmacPrfKeyTest, CopyAssignment) {
  absl::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/16);
  absl::StatusOr<HmacPrfKey> key =
      HmacPrfKey::Create(*parameters, secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<HmacPrfParameters> other_parameters =
      HmacPrfParameters::Create(
          /*key_size_in_bytes=*/32, HmacPrfParameters::HashType::kSha512);
  ASSERT_THAT(other_parameters, IsOk());

  RestrictedData other_secret = RestrictedData(/*num_random_bytes=*/32);
  absl::StatusOr<HmacPrfKey> copy = HmacPrfKey::Create(
      *other_parameters, other_secret, GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *key;

  EXPECT_THAT(*copy, Eq(*key));
}

TEST(HmacPrfKeyTest, MoveConstructor) {
  absl::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/16);
  absl::StatusOr<HmacPrfKey> key =
      HmacPrfKey::Create(*parameters, secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  HmacPrfKey expected = *key;
  HmacPrfKey moved(std::move(*key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(HmacPrfKeyTest, MoveAssignment) {
  absl::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/16);
  absl::StatusOr<HmacPrfKey> key =
      HmacPrfKey::Create(*parameters, secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<HmacPrfParameters> other_parameters =
      HmacPrfParameters::Create(
          /*key_size_in_bytes=*/32, HmacPrfParameters::HashType::kSha512);
  ASSERT_THAT(other_parameters, IsOk());

  RestrictedData other_secret = RestrictedData(/*num_random_bytes=*/32);
  absl::StatusOr<HmacPrfKey> moved = HmacPrfKey::Create(
      *other_parameters, other_secret, GetPartialKeyAccess());
  ASSERT_THAT(moved, IsOk());

  HmacPrfKey expected = *key;
  *moved = std::move(*key);

  EXPECT_THAT(*moved, Eq(expected));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
