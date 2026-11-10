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

#include "tink/jwt/subtle/create_jwt_ml_dsa_public_key_sign.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/jwt/jwt_ml_dsa_private_key.h"
#include "tink/jwt/jwt_ml_dsa_public_key.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/subtle/create_jwt_ml_dsa_key.h"
#include "tink/jwt/subtle/create_jwt_ml_dsa_public_key_verify.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/partial_key_access.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::testing::Not;

TEST(CreateJwtMlDsaPublicKeySignTest, SignAndVerifyWithoutKid) {
  absl::StatusOr<JwtMlDsaParameters> params =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kIgnored,
                                 JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<JwtMlDsaPrivateKey> private_key =
      CreateJwtMlDsaPrivateKey(*params, /*id_requirement=*/std::nullopt);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> signer =
      CreateJwtMlDsaPublicKeySign(*private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verifier =
      CreateJwtMlDsaPublicKeyVerify(private_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<std::string> compact = (*signer)->SignAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());

  absl::StatusOr<VerifiedJwt> verified_jwt =
      (*verifier)->VerifyAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), IsOkAndHolds("issuer"));
}

TEST(CreateJwtMlDsaPublicKeySignTest, SignAndVerifyWithKeyIdKid) {
  absl::StatusOr<JwtMlDsaParameters> params = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<JwtMlDsaPrivateKey> private_key =
      CreateJwtMlDsaPrivateKey(*params, /*id_requirement=*/0x12345678);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> signer =
      CreateJwtMlDsaPublicKeySign(*private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verifier =
      CreateJwtMlDsaPublicKeyVerify(private_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<std::string> compact = (*signer)->SignAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());

  absl::StatusOr<VerifiedJwt> verified_jwt =
      (*verifier)->VerifyAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), IsOkAndHolds("issuer"));

  // Verification with a key that has a different ID requirement fails.
  absl::StatusOr<JwtMlDsaPublicKey> wrong_kid_public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicKeyBytes(private_key->GetPublicKey().GetPublicKeyBytes(
              GetPartialKeyAccess()))
          .SetIdRequirement(0x87654321)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(wrong_kid_public_key, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> wrong_kid_verifier =
      CreateJwtMlDsaPublicKeyVerify(*wrong_kid_public_key);
  ASSERT_THAT(wrong_kid_verifier, IsOk());
  EXPECT_THAT((*wrong_kid_verifier)->VerifyAndDecode(*compact, *validator),
              Not(IsOk()));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
