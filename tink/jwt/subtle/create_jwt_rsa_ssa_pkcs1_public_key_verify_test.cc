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

#include "tink/jwt/subtle/create_jwt_rsa_ssa_pkcs1_public_key_verify.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/jwt/internal/testing/jwt_rsa_ssa_test_vectors.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_public_key.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/subtle/create_jwt_rsa_ssa_pkcs1_public_key_sign.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/partial_key_access.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::crypto::tink::jwt_internal::CreateJwtRsaSsaPkcs1TestVectors;
using ::crypto::tink::jwt_internal::GetJwtRsaSsaPkcs1TestVector;
using ::crypto::tink::jwt_internal::JwtRsaSsaPkcs1TestVector;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using CreateJwtRsaSsaPkcs1PublicKeyVerifyTest =
    TestWithParam<JwtRsaSsaPkcs1TestVector>;

INSTANTIATE_TEST_SUITE_P(CreateJwtRsaSsaPkcs1PublicKeyVerifyTests,
                         CreateJwtRsaSsaPkcs1PublicKeyVerifyTest,
                         ValuesIn(CreateJwtRsaSsaPkcs1TestVectors()));

TEST_P(CreateJwtRsaSsaPkcs1PublicKeyVerifyTest,
       VerifySuccessAndModifiedTokenFails) {
  const JwtRsaSsaPkcs1TestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> signer =
      CreateJwtRsaSsaPkcs1PublicKeySign(test_vector.key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verifier =
      CreateJwtRsaSsaPkcs1PublicKeyVerify(test_vector.key.GetPublicKey());
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

TEST(CreateJwtRsaSsaPkcs1PublicKeyVerifySingleTest,
     VerifyFailsWithDifferentKid) {
  const JwtRsaSsaPkcs1TestVector& test_vector =
      GetJwtRsaSsaPkcs1TestVector(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256);
  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> signer =
      CreateJwtRsaSsaPkcs1PublicKeySign(test_vector.key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key_different_kid =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(test_vector.key.GetPublicKey().GetParameters())
          .SetModulus(
              test_vector.key.GetPublicKey().GetModulus(GetPartialKeyAccess()))
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key_different_kid, IsOk());

  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verifier =
      CreateJwtRsaSsaPkcs1PublicKeyVerify(*public_key_different_kid);
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
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
