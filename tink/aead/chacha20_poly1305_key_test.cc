// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/aead/chacha20_poly1305_key.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/aead/chacha20_poly1305_parameters.h"
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
  ChaCha20Poly1305Parameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using ChaCha20Poly1305KeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    ChaCha20Poly1305KeyTestSuite, ChaCha20Poly1305KeyTest,
    Values(TestCase{ChaCha20Poly1305Parameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{ChaCha20Poly1305Parameters::Variant::kCrunchy, 0x01030005,
                    std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{ChaCha20Poly1305Parameters::Variant::kNoPrefix,
                    absl::nullopt, ""}));

TEST_P(ChaCha20Poly1305KeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<ChaCha20Poly1305Parameters> params =
      ChaCha20Poly1305Parameters::Create(test_case.variant);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);
  absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      test_case.variant, secret, test_case.id_requirement,
      GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(key->GetParameters(), Eq(*params));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetOutputPrefix(), Eq(test_case.output_prefix));
}

TEST(ChaCha20Poly1305KeyTest, CreateKeyWithInvalidVariantFails) {
  EXPECT_THAT(ChaCha20Poly1305Key::Create(
                  ChaCha20Poly1305Parameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements,
                  /*key_bytes=*/RestrictedData(/*num_random_bytes=*/32),
                  /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ChaCha20Poly1305KeyTest, CreateKeyWithInvalidKeySizeFails) {
  // Key material must be 32 bytes.
  RestrictedData invalid_secret = RestrictedData(/*num_random_bytes=*/16);

  EXPECT_THAT(ChaCha20Poly1305Key::Create(
                  ChaCha20Poly1305Parameters::Variant::kTink, invalid_secret,
                  /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ChaCha20Poly1305KeyTest, CreateKeyWithInvalidIdRequirementFails) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  EXPECT_THAT(ChaCha20Poly1305Key::Create(
                  ChaCha20Poly1305Parameters::Variant::kNoPrefix, secret,
                  /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(ChaCha20Poly1305Key::Create(
                  ChaCha20Poly1305Parameters::Variant::kTink, secret,
                  /*id_requirement=*/absl::nullopt, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(ChaCha20Poly1305KeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      test_case.variant, secret, test_case.id_requirement,
      GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<ChaCha20Poly1305Key> other_key = ChaCha20Poly1305Key::Create(
      test_case.variant, secret, test_case.id_requirement,
      GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(ChaCha20Poly1305KeyTest, DifferentVariantNotEqual) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kCrunchy, secret,
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<ChaCha20Poly1305Key> other_key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink, secret,
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(ChaCha20Poly1305KeyTest, DifferentSecretDataNotEqual) {
  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);
  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink, secret1,
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<ChaCha20Poly1305Key> other_key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink, secret2,
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(ChaCha20Poly1305KeyTest, DifferentIdRequirementNotEqual) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink, secret,
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<ChaCha20Poly1305Key> other_key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink, secret,
      /*id_requirement=*/0x02030405, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(ChaCha20Poly1305KeyTest, CopyConstructor) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink, secret,
      /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  ChaCha20Poly1305Key copy(*key);

  EXPECT_THAT(copy.GetParameters().GetVariant(),
              Eq(ChaCha20Poly1305Parameters::Variant::kTink));
  EXPECT_THAT(copy.GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(copy.GetIdRequirement(), Eq(0x123));
}

TEST(ChaCha20Poly1305KeyTest, CopyAssignment) {
  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink, secret1,
      /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<ChaCha20Poly1305Key> copy = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kNoPrefix, secret2,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *key;

  EXPECT_THAT(copy->GetParameters().GetVariant(),
              Eq(ChaCha20Poly1305Parameters::Variant::kTink));
  EXPECT_THAT(copy->GetKeyBytes(GetPartialKeyAccess()), Eq(secret1));
  EXPECT_THAT(copy->GetIdRequirement(), Eq(0x123));
}

TEST(ChaCha20Poly1305KeyTest, MoveConstructor) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink, secret,
      /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  ChaCha20Poly1305Key move = std::move(*key);

  EXPECT_THAT(move.GetParameters().GetVariant(),
              Eq(ChaCha20Poly1305Parameters::Variant::kTink));
  EXPECT_THAT(move.GetKeyBytes(GetPartialKeyAccess()), Eq(secret));
  EXPECT_THAT(move.GetIdRequirement(), Eq(0x123));
}

TEST(ChaCha20Poly1305KeyTest, MoveAssignment) {
  RestrictedData secret1 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink, secret1,
      /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<ChaCha20Poly1305Key> move = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kNoPrefix, secret2,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(move, IsOk());

  *move = std::move(*key);

  EXPECT_THAT(move->GetParameters().GetVariant(),
              Eq(ChaCha20Poly1305Parameters::Variant::kTink));
  EXPECT_THAT(move->GetKeyBytes(GetPartialKeyAccess()), Eq(secret1));
  EXPECT_THAT(move->GetIdRequirement(), Eq(0x123));
}

TEST(ChaCha20Poly1305KeyTest, Clone) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kTink, secret,
      /*id_requirement=*/0x123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
