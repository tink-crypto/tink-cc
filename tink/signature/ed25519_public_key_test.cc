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

#include "tink/signature/ed25519_public_key.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/internal/testing/ed25519_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::Values;

// Returns static Ed25519 public key from GetEd25519TestVector().
const Ed25519PublicKey& GetTestPublicKey() {
  const Ed25519PublicKey* key = dynamic_cast<const Ed25519PublicKey*>(
      &internal::GetEd25519TestVector(Ed25519Parameters::Variant::kNoPrefix)
           .signature_private_key->GetPublicKey());
  ABSL_CHECK_NE(key, nullptr);
  return *key;
}

// Test case from RFC 8032 Section 7.1.
const std::string& GetOtherPublicKeyBytes() {
  static const absl::NoDestructor<std::string> bytes(test::HexDecodeOrDie(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
  return *bytes;
}

struct TestCase {
  Ed25519Parameters::Variant variant;
  std::optional<int> id_requirement;
  std::string output_prefix;
};

using Ed25519PublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    Ed25519PublicKeyTestSuite, Ed25519PublicKeyTest,
    Values(TestCase{Ed25519Parameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{Ed25519Parameters::Variant::kCrunchy, 0x01030005,
                    std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{Ed25519Parameters::Variant::kLegacy, 0x07080910,
                    std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{Ed25519Parameters::Variant::kNoPrefix, std::nullopt, ""}));

TEST_P(Ed25519PublicKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(params, IsOk());

  const Ed25519PublicKey& test_key = GetTestPublicKey();

  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *params, test_key.GetPublicKeyBytes(GetPartialKeyAccess()),
      test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*params));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(public_key->GetPublicKeyBytes(GetPartialKeyAccess()),
              Eq(test_key.GetPublicKeyBytes(GetPartialKeyAccess())));
}

TEST(Ed25519PublicKeyTest, CreateWithInvalidPublicKeyLength) {
  absl::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes =
      std::string(GetTestPublicKey().GetPublicKeyBytes(GetPartialKeyAccess()))
          .substr(0, 31);

  EXPECT_THAT(
      Ed25519PublicKey::Create(*params, public_key_bytes,
                               /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Ed25519PublicKeyTest, CreateKeyWithInvalidIdRequirementFails) {
  absl::StatusOr<Ed25519Parameters> no_prefix_params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_params, IsOk());

  absl::StatusOr<Ed25519Parameters> tink_params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  const Ed25519PublicKey& test_key = GetTestPublicKey();

  EXPECT_THAT(
      Ed25519PublicKey::Create(
          *no_prefix_params, test_key.GetPublicKeyBytes(GetPartialKeyAccess()),
          /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(
      Ed25519PublicKey::Create(
          *tink_params, test_key.GetPublicKeyBytes(GetPartialKeyAccess()),
          /*id_requirement=*/std::nullopt, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(Ed25519PublicKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(test_case.variant);
  ASSERT_THAT(params, IsOk());

  const Ed25519PublicKey& test_key = GetTestPublicKey();

  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *params, test_key.GetPublicKeyBytes(GetPartialKeyAccess()),
      test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<Ed25519PublicKey> other_public_key = Ed25519PublicKey::Create(
      *params, test_key.GetPublicKeyBytes(GetPartialKeyAccess()),
      test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST(Ed25519PublicKeyTest, DifferentVariantNotEqual) {
  absl::StatusOr<Ed25519Parameters> crunchy_params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kCrunchy);
  ASSERT_THAT(crunchy_params, IsOk());

  absl::StatusOr<Ed25519Parameters> tink_params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());

  const Ed25519PublicKey& test_key = GetTestPublicKey();

  absl::StatusOr<Ed25519PublicKey> crunchy_public_key =
      Ed25519PublicKey::Create(
          *crunchy_params, test_key.GetPublicKeyBytes(GetPartialKeyAccess()),
          /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(crunchy_public_key, IsOk());

  absl::StatusOr<Ed25519PublicKey> tink_public_key = Ed25519PublicKey::Create(
      *tink_params, test_key.GetPublicKeyBytes(GetPartialKeyAccess()),
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(tink_public_key, IsOk());

  EXPECT_TRUE(*tink_public_key != *crunchy_public_key);
  EXPECT_TRUE(*crunchy_public_key != *tink_public_key);
  EXPECT_FALSE(*tink_public_key == *crunchy_public_key);
  EXPECT_FALSE(*crunchy_public_key == *tink_public_key);
}

TEST(Ed25519PublicKeyTest, DifferentPublicKeyBytesNotEqual) {
  absl::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  const Ed25519PublicKey& test_key = GetTestPublicKey();

  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *params, test_key.GetPublicKeyBytes(GetPartialKeyAccess()),
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<Ed25519PublicKey> other_public_key = Ed25519PublicKey::Create(
      *params, GetOtherPublicKeyBytes(), /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(Ed25519PublicKeyTest, DifferentIdRequirementNotEqual) {
  absl::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  const Ed25519PublicKey& test_key = GetTestPublicKey();

  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *params, test_key.GetPublicKeyBytes(GetPartialKeyAccess()),
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<Ed25519PublicKey> other_public_key = Ed25519PublicKey::Create(
      *params, test_key.GetPublicKeyBytes(GetPartialKeyAccess()),
      /*id_requirement=*/0x02030405, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(Ed25519PublicKeyTest, Clone) {
  absl::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  const Ed25519PublicKey& test_key = GetTestPublicKey();

  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *params, test_key.GetPublicKeyBytes(GetPartialKeyAccess()),
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = public_key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*public_key));
}

TEST(Ed25519PublicKeyTest, CopyConstructor) {
  absl::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  const Ed25519PublicKey& test_key = GetTestPublicKey();

  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *params, test_key.GetPublicKeyBytes(GetPartialKeyAccess()),
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  Ed25519PublicKey copy(*public_key);

  EXPECT_THAT(copy, Eq(*public_key));
}

TEST(Ed25519PublicKeyTest, CopyAssignment) {
  absl::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  const Ed25519PublicKey& test_key = GetTestPublicKey();

  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *params, test_key.GetPublicKeyBytes(GetPartialKeyAccess()),
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<Ed25519Parameters> other_params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix);
  ASSERT_THAT(other_params, IsOk());

  absl::StatusOr<Ed25519PublicKey> copy = Ed25519PublicKey::Create(
      *other_params, GetOtherPublicKeyBytes(),
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *public_key;

  EXPECT_THAT(*copy, Eq(*public_key));
}

TEST(Ed25519PublicKeyTest, MoveConstructor) {
  absl::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  const Ed25519PublicKey& test_key = GetTestPublicKey();

  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *params, test_key.GetPublicKeyBytes(GetPartialKeyAccess()),
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  Ed25519PublicKey expected = *public_key;
  Ed25519PublicKey moved(std::move(*public_key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(Ed25519PublicKeyTest, MoveAssignment) {
  absl::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  const Ed25519PublicKey& test_key = GetTestPublicKey();

  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *params, test_key.GetPublicKeyBytes(GetPartialKeyAccess()),
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<Ed25519Parameters> other_params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix);
  ASSERT_THAT(other_params, IsOk());

  absl::StatusOr<Ed25519PublicKey> moved = Ed25519PublicKey::Create(
      *other_params, GetOtherPublicKeyBytes(),
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(moved, IsOk());

  Ed25519PublicKey expected = *public_key;
  *moved = std::move(*public_key);

  EXPECT_THAT(*moved, Eq(expected));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
