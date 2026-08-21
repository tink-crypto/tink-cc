// Copyright 2026 Google LLC
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

#include "tink/jwt/jwt_ml_dsa_public_key.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/jwt/internal/testing/jwt_ml_dsa_test_vectors.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  JwtMlDsaParameters::KidStrategy kid_strategy;
  JwtMlDsaParameters::Algorithm algorithm;
  std::optional<std::string> custom_kid;
  std::optional<int> id_requirement;
  std::optional<std::string> expected_kid;
  std::string public_key_bytes;
};

using JwtMlDsaPublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    JwtMlDsaPublicKeyTestSuite, JwtMlDsaPublicKeyTest,
    Values(
        TestCase{JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
                 JwtMlDsaParameters::Algorithm::kMlDsa44,
                 /*custom_kid=*/std::nullopt, /*id_requirement=*/123,
                 /*expected_kid=*/"AAAAew",
                 /*public_key_bytes=*/
                 jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes},
        TestCase{JwtMlDsaParameters::KidStrategy::kCustom,
                 JwtMlDsaParameters::Algorithm::kMlDsa65,
                 /*custom_kid=*/"custom_kid",
                 /*id_requirement=*/std::nullopt,
                 /*expected_kid=*/"custom_kid",
                 /*public_key_bytes=*/
                 jwt_internal::CreateJwtMlDsa65TestVector().public_key_bytes},
        TestCase{JwtMlDsaParameters::KidStrategy::kIgnored,
                 JwtMlDsaParameters::Algorithm::kMlDsa87,
                 /*custom_kid=*/std::nullopt,
                 /*id_requirement=*/std::nullopt,
                 /*expected_kid=*/std::nullopt,
                 /*public_key_bytes=*/
                 jwt_internal::CreateJwtMlDsa87TestVector().public_key_bytes}));

TEST_P(JwtMlDsaPublicKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<JwtMlDsaParameters> params =
      JwtMlDsaParameters::Create(test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(params, IsOk());

  JwtMlDsaPublicKey::Builder builder =
      JwtMlDsaPublicKey::Builder().SetParameters(*params).SetPublicKeyBytes(
          test_case.public_key_bytes);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }
  absl::StatusOr<JwtMlDsaPublicKey> key = builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*params));
  EXPECT_THAT(key->GetPublicKeyBytes(GetPartialKeyAccess()),
              Eq(test_case.public_key_bytes));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetKid(), Eq(test_case.expected_kid));
}

TEST(JwtMlDsaPublicKeyTest, CustomKidPreservesStringViewBounds) {
  absl::StatusOr<JwtMlDsaParameters> params =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kCustom,
                                 JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(params, IsOk());

  std::string backing = "custom_kid|secret";
  absl::string_view custom_kid(backing.data(), /*len=*/10);
  absl::StatusOr<JwtMlDsaPublicKey> key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa65TestVector().public_key_bytes)
          .SetCustomKid(custom_kid)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  ASSERT_TRUE(key->GetKid().has_value());
  EXPECT_EQ(*key->GetKid(), "custom_kid");
}

TEST(JwtMlDsaPublicKeyTest, CreateKeyWithInvalidPublicKeyBytesFails) {
  absl::StatusOr<JwtMlDsaParameters> params =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kIgnored,
                                 JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes =
      jwt_internal::CreateJwtMlDsa65TestVector().public_key_bytes;

  JwtMlDsaPublicKey::Builder builder =
      JwtMlDsaPublicKey::Builder().SetParameters(*params).SetPublicKeyBytes(
          public_key_bytes.substr(0, public_key_bytes.size() - 1));

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid JWT ML-DSA public key size")));
}

TEST(JwtMlDsaPublicKeyTest, CreateBase64EncodedKidWithoutIdRequirementFails) {
  absl::StatusOr<JwtMlDsaParameters> params = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(params, IsOk());

  JwtMlDsaPublicKey::Builder builder =
      JwtMlDsaPublicKey::Builder().SetParameters(*params).SetPublicKeyBytes(
          jwt_internal::CreateJwtMlDsa65TestVector().public_key_bytes);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key without ID requirement "
                                 "with parameters with ID requirement")));
}

TEST(JwtMlDsaPublicKeyTest, CreateBase64EncodedKidWithCustomKidFails) {
  absl::StatusOr<JwtMlDsaParameters> params = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(params, IsOk());

  JwtMlDsaPublicKey::Builder builder =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa65TestVector().public_key_bytes)
          .SetIdRequirement(123)
          .SetCustomKid("custom_kid");

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Custom kid must not be set for "
                                 "KidStrategy::kBase64EncodedKeyId")));
}

TEST(JwtMlDsaPublicKeyTest, CreateCustomKidWithIdRequirementFails) {
  absl::StatusOr<JwtMlDsaParameters> params =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kCustom,
                                 JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(params, IsOk());

  JwtMlDsaPublicKey::Builder builder =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa65TestVector().public_key_bytes)
          .SetCustomKid("custom_kid")
          .SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement with "
                                 "parameters without ID requirement")));
}

TEST(JwtMlDsaPublicKeyTest, CreateCustomKidWithoutCustomKidFails) {
  absl::StatusOr<JwtMlDsaParameters> params =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kCustom,
                                 JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(params, IsOk());

  JwtMlDsaPublicKey::Builder builder =
      JwtMlDsaPublicKey::Builder().SetParameters(*params).SetPublicKeyBytes(
          jwt_internal::CreateJwtMlDsa65TestVector().public_key_bytes);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Custom kid must be set")));
}

TEST(JwtMlDsaPublicKeyTest, CreateIgnoredKidWithIdRequirementFails) {
  absl::StatusOr<JwtMlDsaParameters> params =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kIgnored,
                                 JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(params, IsOk());

  JwtMlDsaPublicKey::Builder builder =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa65TestVector().public_key_bytes)
          .SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement with "
                                 "parameters without ID requirement")));
}

TEST(JwtMlDsaPublicKeyTest, CreateIgnoredKidWithCustomKidFails) {
  absl::StatusOr<JwtMlDsaParameters> params =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kIgnored,
                                 JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(params, IsOk());

  JwtMlDsaPublicKey::Builder builder =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa65TestVector().public_key_bytes)
          .SetCustomKid("custom_kid");

  EXPECT_THAT(
      builder.Build(GetPartialKeyAccess()),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Custom kid must not be set for KidStrategy::kIgnored")));
}

TEST(JwtMlDsaPublicKeyTest, CreateWithMissingParametersFails) {
  JwtMlDsaPublicKey::Builder builder =
      JwtMlDsaPublicKey::Builder().SetPublicKeyBytes(
          jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("JWT ML-DSA parameters must be specified")));
}

TEST(JwtMlDsaPublicKeyTest, CreateWithMissingPublicKeyBytesFails) {
  absl::StatusOr<JwtMlDsaParameters> params =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kIgnored,
                                 JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(params, IsOk());

  JwtMlDsaPublicKey::Builder builder =
      JwtMlDsaPublicKey::Builder().SetParameters(*params);

  EXPECT_THAT(
      builder.Build(GetPartialKeyAccess()),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("JWT ML-DSA public key bytes must be specified")));
}

TEST_P(JwtMlDsaPublicKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<JwtMlDsaParameters> params =
      JwtMlDsaParameters::Create(test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(params, IsOk());

  JwtMlDsaPublicKey::Builder builder =
      JwtMlDsaPublicKey::Builder().SetParameters(*params).SetPublicKeyBytes(
          test_case.public_key_bytes);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }
  absl::StatusOr<JwtMlDsaPublicKey> key = builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  JwtMlDsaPublicKey::Builder other_builder =
      JwtMlDsaPublicKey::Builder().SetParameters(*params).SetPublicKeyBytes(
          test_case.public_key_bytes);
  if (test_case.id_requirement.has_value()) {
    other_builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    other_builder.SetCustomKid(*test_case.custom_kid);
  }
  absl::StatusOr<JwtMlDsaPublicKey> other_key =
      other_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(JwtMlDsaPublicKeyTest, DifferentPublicKeyBytesNotEqual) {
  absl::StatusOr<JwtMlDsaParameters> params = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(params, IsOk());

  std::string other_public_key_bytes =
      jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes;
  other_public_key_bytes[0] ^= 1;

  absl::StatusOr<JwtMlDsaPublicKey> key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> other_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(other_public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(JwtMlDsaPublicKeyTest, DifferentIdRequirementNotEqual) {
  absl::StatusOr<JwtMlDsaParameters> params = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes =
      jwt_internal::CreateJwtMlDsa65TestVector().public_key_bytes;

  absl::StatusOr<JwtMlDsaPublicKey> key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> other_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(public_key_bytes)
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(JwtMlDsaPublicKeyTest, DifferentCustomKidNotEqual) {
  absl::StatusOr<JwtMlDsaParameters> params =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kCustom,
                                 JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes =
      jwt_internal::CreateJwtMlDsa65TestVector().public_key_bytes;

  absl::StatusOr<JwtMlDsaPublicKey> key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(public_key_bytes)
          .SetCustomKid("custom_kid")
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> other_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(public_key_bytes)
          .SetCustomKid("other_custom_kid")
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(JwtMlDsaPublicKeyTest, Clone) {
  absl::StatusOr<JwtMlDsaParameters> params = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa65TestVector().public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = public_key->Clone();

  EXPECT_THAT(*cloned_key, Eq(*public_key));
}

TEST(JwtMlDsaPublicKeyTest, CopyConstructor) {
  absl::StatusOr<JwtMlDsaParameters> params = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  JwtMlDsaPublicKey copy(*public_key);

  EXPECT_THAT(copy, Eq(*public_key));
}

TEST(JwtMlDsaPublicKeyTest, CopyAssignment) {
  absl::StatusOr<JwtMlDsaParameters> params = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(params, IsOk());

  std::string other_public_key_bytes =
      jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes;
  other_public_key_bytes[0] ^= 1;

  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> copy =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(other_public_key_bytes)
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *public_key;

  EXPECT_THAT(*copy, Eq(*public_key));
}

TEST(JwtMlDsaPublicKeyTest, MoveConstructor) {
  absl::StatusOr<JwtMlDsaParameters> params = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  JwtMlDsaPublicKey expected(*public_key);
  JwtMlDsaPublicKey moved(std::move(*public_key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(JwtMlDsaPublicKeyTest, MoveAssignment) {
  absl::StatusOr<JwtMlDsaParameters> params = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(params, IsOk());

  std::string other_public_key_bytes =
      jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes;
  other_public_key_bytes[0] ^= 1;

  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> moved =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(other_public_key_bytes)
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(moved, IsOk());

  JwtMlDsaPublicKey expected(*public_key);
  *moved = std::move(*public_key);

  EXPECT_THAT(*moved, Eq(expected));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
