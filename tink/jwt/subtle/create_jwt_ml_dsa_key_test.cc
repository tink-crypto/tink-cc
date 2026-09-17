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

#include "tink/jwt/subtle/create_jwt_ml_dsa_key.h"

#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/jwt/jwt_ml_dsa_private_key.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::IsFalse;

TEST(CreateJwtMlDsaKeyTest, CreateJwtMlDsaPrivateKeyWorks) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaPrivateKey> private_key =
      CreateJwtMlDsaPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(123));
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
}

TEST(CreateJwtMlDsaKeyTest, CreateJwtMlDsaPrivateKeyWithoutIdRequirement) {
  absl::StatusOr<JwtMlDsaParameters> parameters =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kIgnored,
                                 JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaPrivateKey> private_key =
      CreateJwtMlDsaPrivateKey(*parameters);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->GetIdRequirement().has_value(), IsFalse());
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
}

TEST(CreateJwtMlDsaKeyTest,
     CreateJwtMlDsaPrivateKeyMissingIdRequirementForBase64Fails) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateJwtMlDsaPrivateKey(*parameters),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateJwtMlDsaKeyTest,
     CreateJwtMlDsaPrivateKeyIdRequirementGivenForIgnoredFails) {
  absl::StatusOr<JwtMlDsaParameters> parameters =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kIgnored,
                                 JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateJwtMlDsaPrivateKey(*parameters, /*id_requirement=*/123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateJwtMlDsaKeyTest, CreateJwtMlDsaPrivateKeySuccessiveKeysAreDistinct) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaPrivateKey> key1 =
      CreateJwtMlDsaPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key1, IsOk());

  absl::StatusOr<JwtMlDsaPrivateKey> key2 =
      CreateJwtMlDsaPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(*key1, *key2);
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
