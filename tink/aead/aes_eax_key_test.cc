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
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/key.h"
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

struct TestCase {
  int key_size;
  int iv_size;
  int tag_size;
  AesEaxParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using AesEaxKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    AesEaxParametersBuildTestSuite, AesEaxKeyTest,
    Values(TestCase{/*key_size=*/16,
                    /*iv_size=*/12, /*tag_size=*/12,
                    AesEaxParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{/*key_size=*/24,
                    /*iv_size=*/16, /*tag_size=*/14,
                    AesEaxParameters::Variant::kCrunchy, 0x01030005,
                    std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{/*key_size=*/32, /*iv_size=*/16, /*tag_size=*/16,
                    AesEaxParameters::Variant::kNoPrefix, absl::nullopt, ""}));

TEST_P(AesEaxKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret = RestrictedData(test_case.key_size);
  absl::StatusOr<AesEaxKey> key = AesEaxKey::Create(
      *parameters, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
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
                        /*id_requirement=*/absl::nullopt, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesEaxKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  RestrictedData secret = RestrictedData(test_case.key_size);
  absl::StatusOr<AesEaxKey> key = AesEaxKey::Create(
      *parameters, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesEaxKey> other_key = AesEaxKey::Create(
      *parameters, secret, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(AesEaxKeyTest, DifferentParametersKeysNotEqual) {
  absl::StatusOr<AesEaxParameters> crunchy_parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kCrunchy)
          .Build();
  ASSERT_THAT(crunchy_parameters, IsOk());

  absl::StatusOr<AesEaxParameters> tink_parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesEaxKey> key =
      AesEaxKey::Create(*crunchy_parameters, secret,
                        /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<AesEaxKey> other_key =
      AesEaxKey::Create(*tink_parameters, secret, /*id_requirement=*/0x01020304,
                        GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
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
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesEaxKey> key = AesEaxKey::Create(
      *parameters, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  AesEaxKey copy(*key);

  EXPECT_THAT(copy.GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(copy.GetParameters(), Eq(*parameters));
  EXPECT_THAT(copy.GetIdRequirement(), Eq(0x123));
}

TEST(AesEaxKeyTest, CopyAssignment) {
  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesEaxParameters> parameters1 =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters1, IsOk());

  absl::StatusOr<AesEaxKey> key = AesEaxKey::Create(
      *parameters1, secret1, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/16);

  absl::StatusOr<AesEaxParameters> parameters2 =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(12)
          .SetVariant(AesEaxParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters2, IsOk());

  absl::StatusOr<AesEaxKey> copy =
      AesEaxKey::Create(*parameters2, secret2, /*id_requirement=*/absl::nullopt,
                        GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *key;

  EXPECT_THAT(copy->GetKeyBytes(GetPartialKeyAccess()), Eq(secret1));
  EXPECT_THAT(copy->GetParameters(), Eq(*parameters1));
  EXPECT_THAT(copy->GetIdRequirement(), Eq(0x123));
}

TEST(AesEaxKeyTest, MoveConstructor) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesEaxKey> key = AesEaxKey::Create(
      *parameters, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  AesEaxKey move(std::move(*key));

  EXPECT_THAT(move.GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(move.GetParameters(), Eq(*parameters));
  EXPECT_THAT(move.GetIdRequirement(), Eq(0x123));
}

TEST(AesEaxKeyTest, MoveAssignment) {
  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesEaxParameters> parameters1 =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters1, IsOk());

  absl::StatusOr<AesEaxKey> key = AesEaxKey::Create(
      *parameters1, secret1, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/16);

  absl::StatusOr<AesEaxParameters> parameters2 =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(12)
          .SetVariant(AesEaxParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters2, IsOk());

  absl::StatusOr<AesEaxKey> move =
      AesEaxKey::Create(*parameters2, secret2, /*id_requirement=*/absl::nullopt,
                        GetPartialKeyAccess());
  ASSERT_THAT(move, IsOk());

  *move = std::move(*key);

  EXPECT_THAT(move->GetKeyBytes(GetPartialKeyAccess()), Eq(secret1));
  EXPECT_THAT(move->GetParameters(), Eq(*parameters1));
  EXPECT_THAT(move->GetIdRequirement(), Eq(0x123));
}

TEST(AesEaxKeyTest, Clone) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesEaxKey> key = AesEaxKey::Create(
      *parameters, secret, /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
