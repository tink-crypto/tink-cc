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

#include "tink/jwt/internal/jwt_hmac.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/jwt/internal/testing/jwt_hmac_test_vectors.h"
#include "tink/jwt/jwt_hmac_key.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/partial_key_access.h"

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using JwtHmacTest = TestWithParam<JwtHmacTestVector>;

INSTANTIATE_TEST_SUITE_P(JwtHmacTests, JwtHmacTest,
                         ValuesIn(CreateJwtHmacTestVectors()));

TEST_P(JwtHmacTest, ComputeAndVerifyMac) {
  const JwtHmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<JwtMac>> jwt_mac = NewJwtHmac(test_vector.key);
  ASSERT_THAT(jwt_mac, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());

  absl::StatusOr<std::string> compact =
      (*jwt_mac)->ComputeMacAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());

  absl::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), IsOkAndHolds("issuer"));
}

TEST_P(JwtHmacTest, VerifyFixedTestVector) {
  const JwtHmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<JwtMac>> jwt_mac = NewJwtHmac(test_vector.key);
  ASSERT_THAT(jwt_mac, IsOk());

  EXPECT_THAT((*jwt_mac)->VerifyMacAndDecode(test_vector.signed_jwt,
                                             test_vector.validator),
              IsOk());
}

TEST(JwtHmacSingleTest, VerifyFailsWithModifiedToken) {
  const JwtHmacTestVector& test_vector =
      GetJwtHmacTestVector(JwtHmacParameters::Algorithm::kHs256);
  absl::StatusOr<std::unique_ptr<JwtMac>> jwt_mac = NewJwtHmac(test_vector.key);
  ASSERT_THAT(jwt_mac, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());

  absl::StatusOr<std::string> compact =
      (*jwt_mac)->ComputeMacAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());

  std::string modified_compact = *compact;
  modified_compact.back() ^= 1;
  EXPECT_THAT((*jwt_mac)->VerifyMacAndDecode(modified_compact, *validator),
              Not(IsOk()));
}

TEST(JwtHmacSingleTest, VerifyFailsWithDifferentKid) {
  const JwtHmacTestVector& test_vector =
      GetJwtHmacTestVector(JwtHmacParameters::Algorithm::kHs256);
  absl::StatusOr<std::unique_ptr<JwtMac>> jwt_mac1 =
      NewJwtHmac(test_vector.key);
  ASSERT_THAT(jwt_mac1, IsOk());

  absl::StatusOr<JwtHmacKey> key_different_kid =
      JwtHmacKey::Builder()
          .SetParameters(test_vector.key.GetParameters())
          .SetKeyBytes(test_vector.key.GetKeyBytes(GetPartialKeyAccess()))
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key_different_kid, IsOk());
  absl::StatusOr<std::unique_ptr<JwtMac>> jwt_mac2 =
      NewJwtHmac(*key_different_kid);
  ASSERT_THAT(jwt_mac2, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());

  absl::StatusOr<std::string> compact =
      (*jwt_mac1)->ComputeMacAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());
  EXPECT_THAT((*jwt_mac2)->VerifyMacAndDecode(*compact, *validator),
              Not(IsOk()));
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
