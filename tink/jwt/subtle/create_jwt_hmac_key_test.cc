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

#include "tink/jwt/subtle/create_jwt_hmac_key.h"

#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/jwt/jwt_hmac_key.h"
#include "tink/jwt/jwt_hmac_parameters.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::IsFalse;

TEST(CreateJwtHmacKeyTest, CreateJwtHmacKeyWorksBase64EncodedKeyId) {
  absl::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtHmacKey> key =
      CreateJwtHmacKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement(), Eq(123));
}

TEST(CreateJwtHmacKeyTest, CreateJwtHmacKeyWorksIgnored) {
  absl::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/48, JwtHmacParameters::KidStrategy::kIgnored,
      JwtHmacParameters::Algorithm::kHs384);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtHmacKey> key = CreateJwtHmacKey(*parameters);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement().has_value(), IsFalse());
}

TEST(CreateJwtHmacKeyTest, CreateJwtHmacKeyWorksCustomKid) {
  absl::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/64, JwtHmacParameters::KidStrategy::kCustom,
      JwtHmacParameters::Algorithm::kHs512);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtHmacKey> key =
      CreateJwtHmacKey(*parameters, /*id_requirement=*/std::nullopt,
                       /*custom_kid=*/"my_custom_kid");
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetKid(), Eq("my_custom_kid"));
}

TEST(CreateJwtHmacKeyTest, MissingIdRequirementForBase64KeyIdFails) {
  absl::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateJwtHmacKey(*parameters, /*id_requirement=*/std::nullopt),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateJwtHmacKeyTest, MissingCustomKidForCustomKidStrategyFails) {
  absl::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32, JwtHmacParameters::KidStrategy::kCustom,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateJwtHmacKey(*parameters, /*id_requirement=*/std::nullopt,
                               /*custom_kid=*/std::nullopt),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateJwtHmacKeyTest, SuccessiveKeysAreDistinct) {
  absl::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32,
      JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtHmacKey> key1 =
      CreateJwtHmacKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key1, IsOk());

  absl::StatusOr<JwtHmacKey> key2 =
      CreateJwtHmacKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(*key1, *key2);
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
