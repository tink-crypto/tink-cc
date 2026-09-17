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

#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_key_creator.h"

#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"
#include "tink/partial_key_access.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::Ne;

TEST(JwtRsaSsaPkcs1KeyCreatorTest,
     CreatePrivateJwtRsaSsaPkcs1KeyWorksBase64EncodedKeyId) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> key =
      CreatePrivateJwtRsaSsaPkcs1Key(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement(), Eq(123));
}

TEST(JwtRsaSsaPkcs1KeyCreatorTest, CreatePrivateJwtRsaSsaPkcs1KeyWorksIgnored) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs384)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> key =
      CreatePrivateJwtRsaSsaPkcs1Key(*parameters);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement().has_value(), IsFalse());
}

TEST(JwtRsaSsaPkcs1KeyCreatorTest,
     CreatePrivateJwtRsaSsaPkcs1KeyWorksCustomKid) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs512)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> key =
      CreatePrivateJwtRsaSsaPkcs1Key(*parameters,
                                     /*id_requirement=*/std::nullopt,
                                     /*custom_kid=*/"my_custom_kid");
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetPublicKey().GetKid(), Eq("my_custom_kid"));
}

TEST(JwtRsaSsaPkcs1KeyCreatorTest, MissingIdRequirementForBase64KeyIdFails) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreatePrivateJwtRsaSsaPkcs1Key(*parameters,
                                             /*id_requirement=*/std::nullopt),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(JwtRsaSsaPkcs1KeyCreatorTest, MissingCustomKidForCustomKidStrategyFails) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreatePrivateJwtRsaSsaPkcs1Key(*parameters,
                                             /*id_requirement=*/std::nullopt,
                                             /*custom_kid=*/std::nullopt),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(JwtRsaSsaPkcs1KeyCreatorTest, SuccessiveKeysAreDistinct) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> key1 =
      CreatePrivateJwtRsaSsaPkcs1Key(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key1, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> key2 =
      CreatePrivateJwtRsaSsaPkcs1Key(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key2, IsOk());

  EXPECT_THAT(key1->GetPublicKey().GetModulus(GetPartialKeyAccess()),
              Ne(key2->GetPublicKey().GetModulus(GetPartialKeyAccess())));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
