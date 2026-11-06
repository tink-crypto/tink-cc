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

#include "tink/jwt/internal/jwt_rsa_ssa_pss_sign.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/jwt/internal/jwt_public_key_verify_impl.h"
#include "tink/jwt/internal/testing/jwt_rsa_ssa_test_vectors.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

std::string AlgorithmName(JwtRsaSsaPssParameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPssParameters::Algorithm::kPs256:
      return "PS256";
    case JwtRsaSsaPssParameters::Algorithm::kPs384:
      return "PS384";
    case JwtRsaSsaPssParameters::Algorithm::kPs512:
      return "PS512";
    default:
      return "";
  }
}

using JwtRsaSsaPssSignTest = TestWithParam<JwtRsaSsaPssTestVector>;

INSTANTIATE_TEST_SUITE_P(JwtRsaSsaPssSignTests, JwtRsaSsaPssSignTest,
                         ValuesIn(CreateJwtRsaSsaPssTestVectors()));

TEST_P(JwtRsaSsaPssSignTest, SignAndVerify) {
  const JwtRsaSsaPssTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> signer =
      NewJwtRsaSsaPssSign(test_vector.key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> raw_verifier =
      subtle::RsaSsaPssVerifyBoringSsl::New(
          test_vector.key.GetPublicKey().GetRsaSsaPssPublicKey(
              GetPartialKeyAccess()));
  ASSERT_THAT(raw_verifier, IsOk());

  const JwtRsaSsaPssParameters& params =
      test_vector.key.GetPublicKey().GetParameters();
  std::string algorithm_name = AlgorithmName(params.GetAlgorithm());
  std::unique_ptr<JwtPublicKeyVerifyImpl> verifier;
  if (params.GetKidStrategy() ==
      JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId) {
    verifier = JwtPublicKeyVerifyImpl::WithKid(
        *std::move(raw_verifier), algorithm_name,
        *test_vector.key.GetPublicKey().GetKid());
  } else if (params.GetKidStrategy() ==
             JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    verifier = JwtPublicKeyVerifyImpl::RawWithCustomKid(
        *std::move(raw_verifier), algorithm_name,
        *test_vector.key.GetPublicKey().GetKid());
  } else {
    verifier =
        JwtPublicKeyVerifyImpl::Raw(*std::move(raw_verifier), algorithm_name);
  }

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
      verifier->VerifyAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), IsOkAndHolds("issuer"));
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
