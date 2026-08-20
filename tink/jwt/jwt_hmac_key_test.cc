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

#include "tink/jwt/jwt_hmac_key.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/jwt/internal/testing/jwt_hmac_test_vectors.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
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

using JwtHmacKeyTest = TestWithParam<jwt_internal::JwtHmacTestVector>;

INSTANTIATE_TEST_SUITE_P(JwtHmacKeyTestSuite, JwtHmacKeyTest,
                         ValuesIn(jwt_internal::CreateJwtHmacTestVectors()));

TEST_P(JwtHmacKeyTest, CreateSucceeds) {
  const jwt_internal::JwtHmacTestVector& test_vector = GetParam();
  const JwtHmacKey& key = test_vector.key;

  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetParameters(key.GetParameters())
          .SetKeyBytes(key.GetKeyBytes(GetPartialKeyAccess()));
  if (key.GetIdRequirement().has_value()) {
    builder.SetIdRequirement(*key.GetIdRequirement());
  }
  if (key.GetParameters().GetKidStrategy() ==
      JwtHmacParameters::KidStrategy::kCustom) {
    builder.SetCustomKid(*key.GetKid());
  }
  absl::StatusOr<JwtHmacKey> created_key = builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(created_key, IsOk());

  EXPECT_THAT(created_key->GetParameters(), Eq(key.GetParameters()));
  EXPECT_THAT(created_key->GetKeyBytes(GetPartialKeyAccess()),
              Eq(key.GetKeyBytes(GetPartialKeyAccess())));
  EXPECT_THAT(created_key->GetIdRequirement(), Eq(key.GetIdRequirement()));
  EXPECT_THAT(created_key->GetKid(), Eq(key.GetKid()));
}

TEST(JwtHmacKeyTest, CustomKidPreservesStringViewBounds) {
  const JwtHmacKey& valid_key = jwt_internal::GetJwtHmacTestVector(48).key;

  std::string backing = "custom_kid|secret";
  absl::string_view custom_kid(backing.data(), /*len=*/10);
  absl::StatusOr<JwtHmacKey> key =
      JwtHmacKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetKeyBytes(valid_key.GetKeyBytes(GetPartialKeyAccess()))
          .SetCustomKid(custom_kid)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  ASSERT_TRUE(key->GetKid().has_value());
  EXPECT_EQ(*key->GetKid(), "custom_kid");
}

TEST(JwtHmacKeyTest, CustomKidPreservesEmbeddedNull) {
  const JwtHmacKey& valid_key = jwt_internal::GetJwtHmacTestVector(48).key;

  std::string custom_kid("custom\0kid", 10);
  absl::StatusOr<JwtHmacKey> key =
      JwtHmacKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetKeyBytes(valid_key.GetKeyBytes(GetPartialKeyAccess()))
          .SetCustomKid(custom_kid)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  ASSERT_TRUE(key->GetKid().has_value());
  EXPECT_EQ(*key->GetKid(), custom_kid);
}

TEST(JwtHmacKeyTest, CreateKeyWithMismatchedKeySizeFails) {
  const JwtHmacKey& valid_key = jwt_internal::GetJwtHmacTestVector(32).key;

  // Key material is 16 bytes (another key length, but invalid for this 32-byte
  // param).
  RestrictedData mismatched_secret =
      RestrictedData(std::string(16, 'a'), InsecureSecretKeyAccess::Get());
  JwtHmacKey::Builder builder = JwtHmacKey::Builder()
                                    .SetParameters(valid_key.GetParameters())
                                    .SetKeyBytes(mismatched_secret)
                                    .SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Actual JWT HMAC key size does not match")));
}

TEST(JwtHmacKeyTest, CreateKeyWithoutKeyBytesFails) {
  const JwtHmacKey& valid_key = jwt_internal::GetJwtHmacTestVector(32).key;

  JwtHmacKey::Builder builder = JwtHmacKey::Builder()
                                    .SetParameters(valid_key.GetParameters())
                                    .SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("JWT HMAC key bytes must be specified")));
}

TEST(JwtHmacKeyTest, CreateKeyWithoutParametersFails) {
  const JwtHmacKey& valid_key = jwt_internal::GetJwtHmacTestVector(32).key;

  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetKeyBytes(valid_key.GetKeyBytes(GetPartialKeyAccess()))
          .SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("JWT HMAC parameters must be specified")));
}

TEST(JwtHmacKeyTest, CreateBase64EncodedKidWithoutIdRequirementFails) {
  const JwtHmacKey& valid_key = jwt_internal::GetJwtHmacTestVector(32).key;

  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetKeyBytes(valid_key.GetKeyBytes(GetPartialKeyAccess()));

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key without ID requirement "
                                 "with parameters with ID requirement")));
}

TEST(JwtHmacKeyTest, CreateBase64EncodedKidWithCustomKidFails) {
  const JwtHmacKey& valid_key = jwt_internal::GetJwtHmacTestVector(32).key;

  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetKeyBytes(valid_key.GetKeyBytes(GetPartialKeyAccess()))
          .SetIdRequirement(123)
          .SetCustomKid("custom_kid");

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Custom kid must not be set for "
                                 "KidStrategy::kBase64EncodedKeyId")));
}

TEST(JwtHmacKeyTest, CreateCustomKidWithIdRequirementFails) {
  const JwtHmacKey& valid_key = jwt_internal::GetJwtHmacTestVector(48).key;

  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetKeyBytes(valid_key.GetKeyBytes(GetPartialKeyAccess()))
          .SetCustomKid("custom_kid")
          .SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement with "
                                 "parameters without ID requirement")));
}

TEST(JwtHmacKeyTest, CreateCustomKidWithoutCustomKidFails) {
  const JwtHmacKey& valid_key = jwt_internal::GetJwtHmacTestVector(48).key;

  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetKeyBytes(valid_key.GetKeyBytes(GetPartialKeyAccess()));

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Custom kid must be set")));
}

TEST(JwtHmacKeyTest, CreateIgnoredKidWithIdRequirementFails) {
  const JwtHmacKey& valid_key = jwt_internal::GetJwtHmacTestVector(64).key;

  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetKeyBytes(valid_key.GetKeyBytes(GetPartialKeyAccess()))
          .SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement with "
                                 "parameters without ID requirement")));
}

TEST(JwtHmacKeyTest, CreateIgnoredKidWithCustomKidFails) {
  const JwtHmacKey& valid_key = jwt_internal::GetJwtHmacTestVector(64).key;

  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetKeyBytes(valid_key.GetKeyBytes(GetPartialKeyAccess()))
          .SetCustomKid("custom_kid");

  EXPECT_THAT(
      builder.Build(GetPartialKeyAccess()).status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Custom kid must not be set for KidStrategy::kIgnored")));
}

TEST_P(JwtHmacKeyTest, KeyEquals) {
  const JwtHmacKey& key = GetParam().key;
  JwtHmacKey copy = key;

  EXPECT_TRUE(key == copy);
  EXPECT_TRUE(copy == key);
  EXPECT_FALSE(key != copy);
  EXPECT_FALSE(copy != key);
}

TEST(JwtHmacKeyTest, DifferentParametersNotEqual) {
  const JwtHmacKey& key1 = jwt_internal::GetJwtHmacTestVector(32).key;
  const JwtHmacKey& key2 = jwt_internal::GetJwtHmacTestVector(48).key;

  EXPECT_TRUE(key1 != key2);
  EXPECT_TRUE(key2 != key1);
  EXPECT_FALSE(key1 == key2);
  EXPECT_FALSE(key2 == key1);
}

TEST(JwtHmacKeyTest, DifferentSecretDataNotEqual) {
  const JwtHmacKey& key1 = jwt_internal::GetJwtHmacTestVector(32).key;

  std::string secret2_bytes(key1.GetKeyBytes(GetPartialKeyAccess())
                                .GetSecret(InsecureSecretKeyAccess::Get()));
  secret2_bytes[0] ^= 1;
  RestrictedData secret2 =
      RestrictedData(secret2_bytes, InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtHmacKey> key2 =
      JwtHmacKey::Builder()
          .SetParameters(key1.GetParameters())
          .SetKeyBytes(secret2)
          .SetIdRequirement(*key1.GetIdRequirement())
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key2, IsOk());

  EXPECT_TRUE(key1 != *key2);
  EXPECT_TRUE(*key2 != key1);
  EXPECT_FALSE(key1 == *key2);
  EXPECT_FALSE(*key2 == key1);
}

TEST(JwtHmacKeyTest, DifferentIdRequirementNotEqual) {
  const JwtHmacKey& key1 = jwt_internal::GetJwtHmacTestVector(32).key;

  absl::StatusOr<JwtHmacKey> key2 =
      JwtHmacKey::Builder()
          .SetParameters(key1.GetParameters())
          .SetKeyBytes(key1.GetKeyBytes(GetPartialKeyAccess()))
          .SetIdRequirement(*key1.GetIdRequirement() + 1)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key2, IsOk());

  EXPECT_TRUE(key1 != *key2);
  EXPECT_TRUE(*key2 != key1);
  EXPECT_FALSE(key1 == *key2);
  EXPECT_FALSE(*key2 == key1);
}

TEST(JwtHmacKeyTest, DifferentCustomKidNotEqual) {
  const JwtHmacKey& key1 = jwt_internal::GetJwtHmacTestVector(48).key;

  absl::StatusOr<JwtHmacKey> key2 =
      JwtHmacKey::Builder()
          .SetParameters(key1.GetParameters())
          .SetKeyBytes(key1.GetKeyBytes(GetPartialKeyAccess()))
          .SetCustomKid("other_custom_kid")
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key2, IsOk());

  EXPECT_TRUE(key1 != *key2);
  EXPECT_TRUE(*key2 != key1);
  EXPECT_FALSE(key1 == *key2);
  EXPECT_FALSE(*key2 == key1);
}

TEST(JwtHmacKeyTest, Clone) {
  const JwtHmacKey& key = jwt_internal::GetJwtHmacTestVector(32).key;

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

TEST(JwtHmacKeyTest, CopyConstructor) {
  const JwtHmacKey& key = jwt_internal::GetJwtHmacTestVector(32).key;

  JwtHmacKey copy(key);

  EXPECT_THAT(copy, Eq(key));
}

TEST(JwtHmacKeyTest, CopyAssignment) {
  const JwtHmacKey& key = jwt_internal::GetJwtHmacTestVector(32).key;
  const JwtHmacKey& other_key = jwt_internal::GetJwtHmacTestVector(48).key;

  JwtHmacKey copy = other_key;
  copy = key;

  EXPECT_THAT(copy, Eq(key));
}

TEST(JwtHmacKeyTest, MoveConstructor) {
  JwtHmacKey key = jwt_internal::GetJwtHmacTestVector(32).key;

  JwtHmacKey moved(std::move(key));

  EXPECT_THAT(moved, Eq(jwt_internal::GetJwtHmacTestVector(32).key));
}

TEST(JwtHmacKeyTest, MoveAssignment) {
  JwtHmacKey key = jwt_internal::GetJwtHmacTestVector(32).key;
  JwtHmacKey other_key = jwt_internal::GetJwtHmacTestVector(48).key;

  other_key = std::move(key);

  EXPECT_THAT(other_key, Eq(jwt_internal::GetJwtHmacTestVector(32).key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
