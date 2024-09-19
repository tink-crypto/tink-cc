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

#include "tink/aead/x_aes_gcm_key.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/aead/x_aes_gcm_parameters.h"
#include "tink/partial_key_access.h"
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

constexpr int kKeySize = 32;
constexpr int kSaltSizeBytes = 12;

struct TestCase {
  XAesGcmParameters::Variant variant;
  int salt_size_bytes;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using XAesGcmKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    XAesGcmKeyTestSuite, XAesGcmKeyTest,
    Values(TestCase{XAesGcmParameters::Variant::kTink, /*salt_size_bytes=*/8,
                    0x02030400, std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{XAesGcmParameters::Variant::kTink,
                    /*salt_size_bytes=*/10, 0x01030005,
                    std::string("\x01\x01\x03\x00\x05", 5)},
           TestCase{XAesGcmParameters::Variant::kNoPrefix,
                    /*salt_size_bytes=*/12, absl::nullopt, ""}));

TEST_P(XAesGcmKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  util::StatusOr<XAesGcmParameters> params =
      XAesGcmParameters::Create(test_case.variant, test_case.salt_size_bytes);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(kKeySize);
  util::StatusOr<XAesGcmKey> key = XAesGcmKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(key->GetParameters(), Eq(*params));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetOutputPrefix(), Eq(test_case.output_prefix));
}

TEST(XAesGcmKeyTest, CreateKeyWithInvalidKeySizeFails) {
  // Key material must be 32 bytes.
  RestrictedData invalid_secret = RestrictedData(/*num_random_bytes=*/16);

  util::StatusOr<XAesGcmParameters> params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kSaltSizeBytes);
  ASSERT_THAT(params, IsOk());

  EXPECT_THAT(XAesGcmKey::Create(*params, invalid_secret,
                                 /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(XAesGcmKeyTest, CreateKeyWithInvalidIdRequirementFails) {
  RestrictedData secret = RestrictedData(kKeySize);

  util::StatusOr<XAesGcmParameters> params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kNoPrefix, kSaltSizeBytes);
  ASSERT_THAT(params, IsOk());

  EXPECT_THAT(XAesGcmKey::Create(*params, secret,
                                 /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  util::StatusOr<XAesGcmParameters> other_params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kSaltSizeBytes);
  ASSERT_THAT(params, IsOk());

  EXPECT_THAT(XAesGcmKey::Create(*other_params, secret,
                                 /*id_requirement=*/absl::nullopt,
                                 GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(XAesGcmKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  RestrictedData secret = RestrictedData(kKeySize);

  util::StatusOr<XAesGcmParameters> params =
      XAesGcmParameters::Create(test_case.variant, test_case.salt_size_bytes);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<XAesGcmKey> key = XAesGcmKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<XAesGcmKey> other_key = XAesGcmKey::Create(
      *params, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(XAesGcmKeyTest, DifferentVariantNotEqual) {
  RestrictedData secret = RestrictedData(kKeySize);

  util::StatusOr<XAesGcmParameters> params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kSaltSizeBytes);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<XAesGcmKey> key =
      XAesGcmKey::Create(*params, secret,
                         /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<XAesGcmParameters> other_params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kNoPrefix, kSaltSizeBytes);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<XAesGcmKey> other_key = XAesGcmKey::Create(
      *other_params, secret,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(XAesGcmKeyTest, DifferentSecretDataNotEqual) {
  RestrictedData secret1 = RestrictedData(kKeySize);
  RestrictedData secret2 = RestrictedData(kKeySize);
  int id_requirement = 0x01020304;

  util::StatusOr<XAesGcmParameters> params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kSaltSizeBytes);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<XAesGcmKey> key = XAesGcmKey::Create(
      *params, secret1, id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<XAesGcmKey> other_key = XAesGcmKey::Create(
      *params, secret2, id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(XAesGcmKeyTest, DifferentIdRequirementNotEqual) {
  RestrictedData secret = RestrictedData(kKeySize);

  util::StatusOr<XAesGcmParameters> params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kSaltSizeBytes);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<XAesGcmKey> key =
      XAesGcmKey::Create(*params, secret,
                         /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<XAesGcmKey> other_key =
      XAesGcmKey::Create(*params, secret,
                         /*id_requirement=*/0x02030405, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(XAesGcmKeyTest, DifferentSaltSizeNotEqual) {
  RestrictedData secret = RestrictedData(kKeySize);
  int id_requirement = 0x01020304;

  util::StatusOr<XAesGcmParameters> params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kSaltSizeBytes);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<XAesGcmKey> key = XAesGcmKey::Create(
      *params, secret, id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<XAesGcmParameters> other_params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, /*salt_size_bytes=*/8);
  ASSERT_THAT(other_params, IsOk());

  util::StatusOr<XAesGcmKey> other_key = XAesGcmKey::Create(
      *other_params, secret, id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(XAesGcmKeyTest, CopyConstructor) {
  RestrictedData secret = RestrictedData(kKeySize);

  util::StatusOr<XAesGcmParameters> parameters = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kSaltSizeBytes);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<XAesGcmKey> key = XAesGcmKey::Create(
      *parameters, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  XAesGcmKey copy(*key);

  EXPECT_THAT(copy.GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(copy.GetParameters(), Eq(*parameters));
  EXPECT_THAT(copy.GetIdRequirement(), Eq(0x123));
}

TEST(XAesGcmKeyTest, CopyAssignment) {
  RestrictedData secret1 = RestrictedData(kKeySize);

  util::StatusOr<XAesGcmParameters> parameters1 = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kSaltSizeBytes);
  ASSERT_THAT(parameters1, IsOk());

  util::StatusOr<XAesGcmKey> key = XAesGcmKey::Create(
      *parameters1, secret1, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  RestrictedData secret2 = RestrictedData(kKeySize);

  util::StatusOr<XAesGcmParameters> parameters2 = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kNoPrefix, /*salt_size_bytes=*/10);
  ASSERT_THAT(parameters2, IsOk());

  util::StatusOr<XAesGcmKey> copy = XAesGcmKey::Create(
      *parameters2, secret2,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *key;

  EXPECT_THAT(copy->GetKeyBytes(GetPartialKeyAccess()), Eq(secret1));
  EXPECT_THAT(copy->GetParameters(), Eq(*parameters1));
  EXPECT_THAT(copy->GetIdRequirement(), Eq(0x123));
}

TEST(XAesGcmKeyTest, MoveConstructor) {
  RestrictedData secret = RestrictedData(kKeySize);

  util::StatusOr<XAesGcmParameters> parameters = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kSaltSizeBytes);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<XAesGcmKey> key = XAesGcmKey::Create(
      *parameters, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  XAesGcmKey move(std::move(*key));

  EXPECT_THAT(move.GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(move.GetParameters(), Eq(*parameters));
  EXPECT_THAT(move.GetIdRequirement(), Eq(0x123));
}

TEST(XAesGcmKeyTest, MoveAssignment) {
  RestrictedData secret1 = RestrictedData(kKeySize);

  util::StatusOr<XAesGcmParameters> parameters1 = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kSaltSizeBytes);
  ASSERT_THAT(parameters1, IsOk());

  util::StatusOr<XAesGcmKey> key = XAesGcmKey::Create(
      *parameters1, secret1, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  RestrictedData secret2 = RestrictedData(kKeySize);

  util::StatusOr<XAesGcmParameters> parameters2 = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kNoPrefix, /*salt_size_bytes=*/10);
  ASSERT_THAT(parameters2, IsOk());

  util::StatusOr<XAesGcmKey> move = XAesGcmKey::Create(
      *parameters2, secret2,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(move, IsOk());

  *move = std::move(*key);

  EXPECT_THAT(move->GetKeyBytes(GetPartialKeyAccess()), Eq(secret1));
  EXPECT_THAT(move->GetParameters(), Eq(*parameters1));
  EXPECT_THAT(move->GetIdRequirement(), Eq(0x123));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
