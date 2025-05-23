// Copyright 2021 Google LLC
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

#include "tink/jwt/jwt_key_templates.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "tink/config/global_registry.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/jwt/jwt_mac_config.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_signature_config.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/keyset_handle.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

using ::crypto::tink::test::IsOk;
using google::crypto::tink::KeyTemplate;

namespace crypto {
namespace tink {
namespace {

class JwtMacKeyTemplatesTest : public testing::TestWithParam<KeyTemplate> {
  void SetUp() override { ASSERT_TRUE(JwtMacRegister().ok()); }
};

TEST_P(JwtMacKeyTemplatesTest, CreateComputeVerify) {
  KeyTemplate key_template = GetParam();

  absl::StatusOr<std::unique_ptr<crypto::tink::KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(keyset_handle, IsOk());
  absl::StatusOr<std::unique_ptr<crypto::tink::JwtMac>> jwt_mac =
      (*keyset_handle)
          ->GetPrimitive<crypto::tink::JwtMac>(ConfigGlobalRegistry());
  ASSERT_THAT(jwt_mac, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<std::string> compact =
      (*jwt_mac)->ComputeMacAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  absl::StatusOr<VerifiedJwt> verified_jwt =
      (*jwt_mac)->VerifyMacAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), test::IsOkAndHolds("issuer"));

  absl::StatusOr<JwtValidator> validator2 = JwtValidatorBuilder()
                                                .ExpectIssuer("unknown")
                                                .AllowMissingExpiration()
                                                .Build();
  ASSERT_THAT(validator2, IsOk());
  EXPECT_FALSE((*jwt_mac)->VerifyMacAndDecode(*compact, *validator2).ok());
}

INSTANTIATE_TEST_SUITE_P(JwtMacKeyTemplatesTest, JwtMacKeyTemplatesTest,
                         testing::Values(JwtHs256Template(), JwtHs384Template(),
                                         JwtHs512Template()));

class JwtSignatureKeyTemplatesTest
    : public testing::TestWithParam<KeyTemplate> {
  void SetUp() override { ASSERT_TRUE(JwtSignatureRegister().ok()); }
};

TEST_P(JwtSignatureKeyTemplatesTest, CreateComputeVerify) {
  KeyTemplate key_template = GetParam();

  absl::StatusOr<std::unique_ptr<KeysetHandle>> private_handle =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(private_handle, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> sign =
      (*private_handle)
          ->GetPrimitive<crypto::tink::JwtPublicKeySign>(
              ConfigGlobalRegistry());
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*private_handle)->GetPublicKeysetHandle(KeyGenConfigGlobalRegistry());
  ASSERT_THAT(public_handle, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verify =
      (*public_handle)
          ->GetPrimitive<crypto::tink::JwtPublicKeyVerify>(
              ConfigGlobalRegistry());
  ASSERT_THAT(verify, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<std::string> compact = (*sign)->SignAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  absl::StatusOr<VerifiedJwt> verified_jwt =
      (*verify)->VerifyAndDecode(*compact, *validator);
  ASSERT_THAT(verified_jwt, IsOk());
  EXPECT_THAT(verified_jwt->GetIssuer(), test::IsOkAndHolds("issuer"));

  absl::StatusOr<JwtValidator> validator2 = JwtValidatorBuilder()
                                                .ExpectIssuer("unknown")
                                                .AllowMissingExpiration()
                                                .Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_FALSE((*verify)->VerifyAndDecode(*compact, *validator2).ok());
}

INSTANTIATE_TEST_SUITE_P(
    JwtSignatureKeyTemplatesTest, JwtSignatureKeyTemplatesTest,
    testing::Values(JwtEs256Template(), JwtEs384Template(), JwtEs512Template(),
                    RawJwtEs256Template(), JwtRs256_2048_F4_Template(),
                    JwtRs256_3072_F4_Template(), JwtRs384_3072_F4_Template(),
                    JwtRs512_4096_F4_Template(), RawJwtRs256_2048_F4_Template(),
                    JwtPs256_2048_F4_Template(), JwtPs256_3072_F4_Template(),
                    JwtPs384_3072_F4_Template(), JwtPs512_4096_F4_Template(),
                    RawJwtPs256_2048_F4_Template()));
}  // namespace
}  // namespace tink
}  // namespace crypto
