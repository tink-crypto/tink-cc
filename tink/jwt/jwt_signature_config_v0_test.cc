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

#include "tink/jwt/jwt_signature_config_v0.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/jwt/jwt_key_templates.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_signature_key_gen_config_v0.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/keyset_handle.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyTemplate;
using ::testing::TestWithParam;
using ::testing::Values;

using JwtSignatureV0KeyTypesTest = TestWithParam<KeyTemplate>;

INSTANTIATE_TEST_SUITE_P(JwtSignatureV0KeyTypesTestSuite,
                         JwtSignatureV0KeyTypesTest,
                         Values(RawJwtEs256Template(),
                                RawJwtRs256_2048_F4_Template(),
                                RawJwtPs256_2048_F4_Template()));

TEST_P(JwtSignatureV0KeyTypesTest, GetPrimitive) {
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), KeyGenConfigJwtSignatureV0());
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(KeyGenConfigJwtSignatureV0());
  ASSERT_THAT(public_handle, IsOk());

  util::StatusOr<std::unique_ptr<JwtPublicKeySign>> sign =
      (*handle)->GetPrimitive<JwtPublicKeySign>(ConfigJwtSignatureV0());
  ASSERT_THAT(sign, IsOk());
  util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verify =
      (*public_handle)
          ->GetPrimitive<JwtPublicKeyVerify>(ConfigJwtSignatureV0());
  ASSERT_THAT(verify, IsOk());

  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());

  util::StatusOr<std::string> compact = (*sign)->SignAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());
  EXPECT_THAT((*verify)->VerifyAndDecode(*compact, *validator), IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
