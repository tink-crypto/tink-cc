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

#include "tink/jwt/internal/jwt_signature_config_v0.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "tink/big_integer.h"
#include "tink/configuration.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/jwt/internal/jwt_ecdsa_sign_key_manager.h"
#include "tink/jwt/internal/jwt_ecdsa_verify_key_manager.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pss_sign_key_manager.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pss_verify_key_manager.h"
#include "tink/jwt/internal/jwt_signature_key_gen_config_v0.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_private_key.h"
#include "tink/jwt/jwt_ecdsa_proto_serialization.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/jwt/jwt_key_templates.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyTemplate;
using ::testing::TestWithParam;
using ::testing::Values;

TEST(JwtSignatureV0Test, PrimitiveWrappers) {
  Configuration config;
  ASSERT_THAT(AddJwtSignatureV0(config), IsOk());
  util::StatusOr<const internal::KeysetWrapperStore*> store =
      internal::ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<JwtPublicKeySign>(), IsOk());
  EXPECT_THAT((*store)->Get<JwtPublicKeyVerify>(), IsOk());
}

TEST(JwtSignatureV0Test, KeyManagers) {
  Configuration config;
  ASSERT_THAT(AddJwtSignatureV0(config), IsOk());
  util::StatusOr<const internal::KeyTypeInfoStore*> store =
      internal::ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddJwtSignatureKeyGenV0(key_gen_config), IsOk());
  util::StatusOr<const internal::KeyTypeInfoStore*> key_gen_store =
      internal::KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  for (const internal::KeyTypeInfoStore* s : {*store, *key_gen_store}) {
    EXPECT_THAT(s->Get(JwtEcdsaSignKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(JwtEcdsaVerifyKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(JwtRsaSsaPkcs1SignKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(JwtRsaSsaPkcs1VerifyKeyManager().get_key_type()),
                IsOk());
    EXPECT_THAT(s->Get(JwtRsaSsaPssSignKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(JwtRsaSsaPssVerifyKeyManager().get_key_type()), IsOk());
  }
}

using JwtSignatureV0KeyTypesTest = TestWithParam<KeyTemplate>;

INSTANTIATE_TEST_SUITE_P(
    JwtSignatureV0KeyTypesTestSuite, JwtSignatureV0KeyTypesTest,
    Values(RawJwtEs256Template(), JwtEs256Template(),
           RawJwtRs256_2048_F4_Template(), JwtRs256_2048_F4_Template(),
           RawJwtPs256_2048_F4_Template(), JwtPs256_2048_F4_Template()));

TEST_P(JwtSignatureV0KeyTypesTest, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddJwtSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddJwtSignatureV0(config), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), key_gen_config);
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  util::StatusOr<std::unique_ptr<JwtPublicKeySign>> sign =
      (*handle)->GetPrimitive<JwtPublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<JwtPublicKeyVerify>(config);
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

// From https://datatracker.ietf.org/doc/html/rfc7515.
struct JwtSignatureTestVector {
  std::shared_ptr<const Key> private_key;
  std::string signed_jwt;
};

using JwtDeterministicSignatureTest = TestWithParam<JwtSignatureTestVector>;

TEST_P(JwtDeterministicSignatureTest, SignAndVerify) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddJwtSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddJwtSignatureV0(config), IsOk());

  JwtSignatureTestVector test_vector = GetParam();

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              test_vector.private_key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  util::StatusOr<std::unique_ptr<JwtPublicKeySign>> sign =
      handle->GetPrimitive<JwtPublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  util::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<JwtPublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  // Sign and verify a token.
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

  // Verify the test vector signed JWT.
  util::StatusOr<JwtValidator> test_vector_validator =
      JwtValidatorBuilder()
          .ExpectIssuer("joe")
          .SetFixedNow(absl::FromUnixSeconds(1300819380 - 3600))
          .Build();
  EXPECT_THAT((*verify)->VerifyAndDecode(test_vector.signed_jwt,
                                         *test_vector_validator),
              IsOk());
}

std::string Base64WebSafeDecode(absl::string_view base64_string) {
  std::string dest;
  CHECK(absl::WebSafeBase64Unescape(base64_string, &dest))
      << "Failed to base64 decode.";

  return dest;
}

std::vector<JwtSignatureTestVector> GetJwtSignatureTestVectors() {
  CHECK_OK(RegisterJwtEcdsaProtoSerialization());

  std::vector<JwtSignatureTestVector> res;

  // ES256, https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
  absl::StatusOr<JwtEcdsaParameters> params =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  CHECK_OK(params);
  EcPoint public_point(/*x=*/BigInteger(Base64WebSafeDecode(
                           "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")),
                       /*y=*/BigInteger(Base64WebSafeDecode(
                           "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")));

  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetPublicPoint(public_point)
          .SetParameters(*params)
          .Build(GetPartialKeyAccess());
  CHECK_OK(public_key);
  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *std::move(public_key),
      RestrictedBigInteger(
          Base64WebSafeDecode("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"),
          InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  CHECK_OK(private_key);

  res.push_back(JwtSignatureTestVector{
      /*private_key=*/std::make_shared<JwtEcdsaPrivateKey>(*private_key),
      /*signed_jwt=*/
      "eyJhbGciOiJFUzI1NiJ9"
      "."
      "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
      "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
      "."
      "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
      "pmWQxfKTUJqPP3-Kg6NU1Q"});
  return res;
}

INSTANTIATE_TEST_SUITE_P(JwtDeterministicSignatureTestSuite,
                         JwtDeterministicSignatureTest,
                         testing::ValuesIn(GetJwtSignatureTestVectors()));

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
