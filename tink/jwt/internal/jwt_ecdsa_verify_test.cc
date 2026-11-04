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

#include "tink/jwt/internal/jwt_ecdsa_verify.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/jwt/internal/jwt_ecdsa_sign.h"
#include "tink/jwt/internal/testing/jwt_ecdsa_test_vectors.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/partial_key_access.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using JwtEcdsaVerifyTest = TestWithParam<JwtEcdsaTestVector>;

INSTANTIATE_TEST_SUITE_P(JwtEcdsaVerifyTests, JwtEcdsaVerifyTest,
                         ValuesIn(CreateJwtEcdsaTestVectors()));

TEST_P(JwtEcdsaVerifyTest, VerifySuccessAndModifiedTokenFails) {
  const JwtEcdsaTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> signer =
      NewJwtEcdsaSign(test_vector.key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verifier =
      NewJwtEcdsaVerify(test_vector.key.GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());

  absl::StatusOr<std::string> compact = (*signer)->SignAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());

  absl::StatusOr<VerifiedJwt> verified_jwt =
      (*verifier)->VerifyAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), IsOkAndHolds("issuer"));

  std::string modified_compact = *compact;
  modified_compact.back() ^= 1;
  EXPECT_THAT((*verifier)->VerifyAndDecode(modified_compact, *validator),
              Not(IsOk()));
}

TEST(JwtEcdsaVerifySingleTest, VerifyFailsWithDifferentKid) {
  const JwtEcdsaTestVector& test_vector =
      GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256);
  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> signer =
      NewJwtEcdsaSign(test_vector.key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<JwtEcdsaPublicKey> public_key_different_kid =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(test_vector.key.GetPublicKey().GetParameters())
          .SetPublicPoint(test_vector.key.GetPublicKey().GetPublicPoint(
              GetPartialKeyAccess()))
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key_different_kid, IsOk());

  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verifier =
      NewJwtEcdsaVerify(*public_key_different_kid);
  ASSERT_THAT(verifier, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());

  absl::StatusOr<std::string> compact = (*signer)->SignAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());
  EXPECT_THAT((*verifier)->VerifyAndDecode(*compact, *validator), Not(IsOk()));
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
