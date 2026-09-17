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

#include "tink/jwt/subtle/create_jwt_rsa_ssa_pss_key.h"

#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pss_private_key.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::IsFalse;

TEST(CreateJwtRsaSsaPssKeyTest,
     CreateJwtRsaSsaPssPrivateKeyWorksBase64EncodedKeyId) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> key =
      CreateJwtRsaSsaPssPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement(), Eq(123));
}

TEST(CreateJwtRsaSsaPssKeyTest, CreateJwtRsaSsaPssPrivateKeyWorksIgnored) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs384)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> key =
      CreateJwtRsaSsaPssPrivateKey(*parameters);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement().has_value(), IsFalse());
}

TEST(CreateJwtRsaSsaPssKeyTest, CreateJwtRsaSsaPssPrivateKeyWorksCustomKid) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs512)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kCustom)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> key =
      CreateJwtRsaSsaPssPrivateKey(*parameters, /*id_requirement=*/std::nullopt,
                                   /*custom_kid=*/"my_custom_kid");
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetPublicKey().GetKid(), Eq("my_custom_kid"));
}

TEST(CreateJwtRsaSsaPssKeyTest, MissingIdRequirementForBase64KeyIdFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateJwtRsaSsaPssPrivateKey(*parameters,
                                           /*id_requirement=*/std::nullopt),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateJwtRsaSsaPssKeyTest, MissingCustomKidForCustomKidStrategyFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kCustom)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateJwtRsaSsaPssPrivateKey(*parameters,
                                           /*id_requirement=*/std::nullopt,
                                           /*custom_kid=*/std::nullopt),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateJwtRsaSsaPssKeyTest, SuccessiveKeysAreDistinct) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> key1 =
      CreateJwtRsaSsaPssPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key1, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> key2 =
      CreateJwtRsaSsaPssPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(*key1, *key2);
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
