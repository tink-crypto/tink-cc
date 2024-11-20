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
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

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
  HkdfPrfParameters::HashType hash_type;
  absl::optional<std::string> salt;
};

using HkdfPrfKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    HkdfPrfKeyCreateTestSuite, HkdfPrfKeyTest,
    Values(TestCase{/*key_size=*/16, HkdfPrfParameters::HashType::kSha1,
                    absl::nullopt},
           TestCase{/*key_size=*/16, HkdfPrfParameters::HashType::kSha224,
                    test::HexDecodeOrDie("00010203040506")},
           TestCase{/*key_size=*/16, HkdfPrfParameters::HashType::kSha256,
                    test::HexDecodeOrDie("00010203040506070809")},
           TestCase{/*key_size=*/16, HkdfPrfParameters::HashType::kSha384,
                    test::HexDecodeOrDie("000102030405060708090a0b0c")},
           TestCase{/*key_size=*/32, HkdfPrfParameters::HashType::kSha512,
                    test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f")}));

TEST_P(HkdfPrfKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      test_case.key_size, test_case.hash_type, test_case.salt);
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret = RestrictedData(test_case.key_size);
  util::StatusOr<HkdfPrfKey> key =
      HkdfPrfKey::Create(*parameters, secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement(), Eq(absl::nullopt));
}

TEST(HkdfPrfKeyTest, CreateKeyWithNonMatchingKeySizeFails) {
  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      16, HkdfPrfParameters::HashType::kSha256, /*salt=*/absl::nullopt);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(
      HkdfPrfKey::Create(*parameters, RestrictedData(/*num_random_bytes=*/32),
                         GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Key size does not match HKDF-PRF parameters")));
}

TEST_P(HkdfPrfKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      test_case.key_size, test_case.hash_type, test_case.salt);
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret = RestrictedData(test_case.key_size);
  util::StatusOr<HkdfPrfKey> key =
      HkdfPrfKey::Create(*parameters, secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<HkdfPrfKey> other_key =
      HkdfPrfKey::Create(*parameters, secret, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(HkdfPrfKeyTest, DifferentSecretDataNotEqual) {
  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/16, HkdfPrfParameters::HashType::kSha256,
      /*salt=*/absl::nullopt);
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/16);
  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/16);

  util::StatusOr<HkdfPrfKey> key =
      HkdfPrfKey::Create(*parameters, secret1, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<HkdfPrfKey> other_key =
      HkdfPrfKey::Create(*parameters, secret2, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(HkdfPrfKeyTest, DifferentParametersNotEqual) {
  util::StatusOr<HkdfPrfParameters> parameters1 = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/16, HkdfPrfParameters::HashType::kSha256,
      /*salt=*/absl::nullopt);
  ASSERT_THAT(parameters1, IsOk());

  util::StatusOr<HkdfPrfParameters> parameters2 = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/16, HkdfPrfParameters::HashType::kSha384,
      /*salt=*/absl::nullopt);
  ASSERT_THAT(parameters2, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/16);

  util::StatusOr<HkdfPrfKey> key =
      HkdfPrfKey::Create(*parameters1, secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<HkdfPrfKey> other_key =
      HkdfPrfKey::Create(*parameters2, secret, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(HkdfPrfKeyTest, Clone) {
  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/16, HkdfPrfParameters::HashType::kSha256,
      /*salt=*/absl::nullopt);
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/16);

  util::StatusOr<HkdfPrfKey> key =
      HkdfPrfKey::Create(*parameters, secret, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
