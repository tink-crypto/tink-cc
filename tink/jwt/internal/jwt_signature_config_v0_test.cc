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

#include <cstddef>
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
#include "openssl/bn.h"
#include "tink/big_integer.h"
#include "tink/configuration.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/internal/ssl_unique_ptr.h"
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
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_public_key.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pss_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
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
  absl::StatusOr<const internal::KeysetWrapperStore *> store =
      internal::ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<JwtPublicKeySign>(), IsOk());
  EXPECT_THAT((*store)->Get<JwtPublicKeyVerify>(), IsOk());
}

TEST(JwtSignatureV0Test, KeyManagers) {
  Configuration config;
  ASSERT_THAT(AddJwtSignatureV0(config), IsOk());
  absl::StatusOr<const internal::KeyTypeInfoStore *> store =
      internal::ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddJwtSignatureKeyGenV0(key_gen_config), IsOk());
  absl::StatusOr<const internal::KeyTypeInfoStore *> key_gen_store =
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

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), key_gen_config);
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> sign =
      (*handle)->GetPrimitive<JwtPublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<JwtPublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());

  absl::StatusOr<std::string> compact = (*sign)->SignAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());
  EXPECT_THAT((*verify)->VerifyAndDecode(*compact, *validator), IsOk());
}

struct JwtSignatureTestVector {
  std::shared_ptr<const Key> private_key;
  std::string signed_jwt;
  JwtValidator signed_jwt_validator;
};

using JwtDeterministicSignatureTest = TestWithParam<JwtSignatureTestVector>;

TEST_P(JwtDeterministicSignatureTest, SignAndVerify) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddJwtSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddJwtSignatureV0(config), IsOk());

  JwtSignatureTestVector test_vector = GetParam();

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              test_vector.private_key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> sign =
      handle->GetPrimitive<JwtPublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<JwtPublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  // Sign and verify a token.
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
  EXPECT_THAT((*verify)->VerifyAndDecode(*compact, *validator), IsOk());

  // Verify the test vector signed JWT with the JWT validator.
  EXPECT_THAT((*verify)->VerifyAndDecode(test_vector.signed_jwt,
                                         test_vector.signed_jwt_validator),
              IsOk());
}

std::string Base64WebSafeDecode(absl::string_view base64_string) {
  std::string dest;
  CHECK(absl::WebSafeBase64Unescape(base64_string, &dest))
      << "Failed to base64 decode.";

  return dest;
}

// ES256, https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.3
constexpr absl::string_view kEs256X =
    "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
constexpr absl::string_view kEs256Y =
    "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
constexpr absl::string_view kEs256S =
    "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";

// Taken from:
// https://github.com/C2SP/wycheproof/blob/cd27d6419bedd83cbd24611ec54b6d4bfdb0cdca/testvectors/rsa_pkcs1_2048_test.json#L13
constexpr absl::string_view kN2048Base64 =
    "s1EKK81M5kTFtZSuUFnhKy8FS2WNXaWVmi_fGHG4CLw98-"
    "Yo0nkuUarVwSS0O9pFPcpc3kvPKOe9Tv-6DLS3Qru21aATy2PRqjqJ4CYn71OYtSwM_"
    "ZfSCKvrjXybzgu-sBmobdtYm-sppbdL-GEHXGd8gdQw8DDCZSR6-dPJFAzLZTCdB-Ctwe_"
    "RXPF-ewVdfaOGjkZIzDoYDw7n-OHnsYCYozkbTOcWHpjVevipR-IBpGPi1rvKgFnlcG6d_"
    "tj0hWRl_6cS7RqhjoiNEtxqoJzpXs_"
    "Kg8xbCxXbCchkf11STA8udiCjQWuWI8rcDwl69XMmHJjIQAqhKvOOQ8rYTQ";
constexpr absl::string_view kD2048Base64 =
    "GlAtDupse2niHVg5EB9wVFbtDvhS-0f-"
    "IQcfVMXzPIzrBmxi1yfjLSbFgTcyn4nTGVMlt5UmTBldhUcvdQfb0JYdKVH5NaJrNPCsJNFUkO"
    "ESiptxOJFbx9v6j-OWNXExxUOunJhQc2jZzrCMHGGYo-"
    "2nrqGFoOl2zULCLQDwA9nxnZbqTJr8v-"
    "FEHMyALPsGifWdgExqTk9ATBUXR0XtbLi8iO8LM7oNKoDjXkO8kPNQBS5yAW51sA01ejgcnA1G"
    "cGnKZgiHyYd2Y0n8xDRgtKpRa84Hnt2HuhZDB7dSwnftlSitO6C_"
    "GHc0ntO3lmpsJAEQQJv00PreDGj9rdhH_Q";
constexpr absl::string_view kP2048Base64 =
    "7BJc834xCi_0YmO5suBinWOQAF7IiRPU-3G9TdhWEkSYquupg9e6K9lC5k0iP-t6I69NYF7-"
    "6mvXDTmv6Z01o6oV50oXaHeAk74O3UqNCbLe9tybZ_-FdkYlwuGSNttMQBzjCiVy0-y0-"
    "Wm3rRnFIsAtd0RlZ24aN3bFTWJINIs";
constexpr absl::string_view kQ2048Base64 =
    "wnQqvNmJe9SwtnH5c_yCqPhKv1cF_4jdQZSGI6_p3KYNxlQzkHZ_"
    "6uvrU5V27ov6YbX8vKlKfO91oJFQxUD6lpTdgAStI3GMiJBJIZNpyZ9EWNSvwUj28H34cySpbZ"
    "z3s4XdhiJBShgy-fKURvBQwtWmQHZJ3EGrcOI7PcwiyYc";
constexpr absl::string_view kDp2048Base64 =
    "lql5jSUCY0ALtidzQogWJ-B87N-RGHsBuJ_0cxQYinwg-ySAAVbSyF1WZujfbO_5-YBN362A_"
    "1dn3lbswCnHK_bHF9-fZNqvwprPnceQj5oK1n4g6JSZNsy6GNAhosT-"
    "uwQ0misgR8SQE4W25dDGkdEYsz-BgCsyrCcu8J5C-tU";
constexpr absl::string_view kDq2048Base64 =
    "BVT0GwuH9opFcis74M9KseFlA0wakQAquPKenvni2rb-57JFW6-0IDfp0vflM_"
    "NIoUdBL9cggL58JjP12ALJHDnmvOzj5nXlmZUDPFVzcCDa2eizDQS4KK37kwStVKEaNaT1BwmH"
    "asWxGCNrp2pNfJopHdlgexad4dGCOFaRmZ8";
constexpr absl::string_view kQInv2048Base64 =
    "HGQBidm_6MYjgzIQp2xCDG9E5ddg4lmRbOwq4rFWRWlg_ZXidHZgw4lWIlDwVQSc-"
    "rflwwOVSThKeiquscgk069wlIKoz5tYcCKgCx8HIttQ8zyybcIN0iRdUmXfYe4pg8k4whZ9zuE"
    "h_EtEecI35yjPYzq2CowOzQT85-O6pVk";

BigInteger F4() {
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), 0x10001);
  return BigInteger(
      internal::BignumToString(e.get(), BN_num_bytes(e.get())).value());
}

std::vector<JwtSignatureTestVector> GetJwtSignatureTestVectors() {
  CHECK_OK(RegisterJwtEcdsaProtoSerialization());
  std::vector<JwtSignatureTestVector> res;

  {
    absl::StatusOr<JwtEcdsaParameters> params =
        JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                   JwtEcdsaParameters::Algorithm::kEs256);
    CHECK_OK(params);
    EcPoint public_point(/*x=*/BigInteger(Base64WebSafeDecode(kEs256X)),
                         /*y=*/BigInteger(Base64WebSafeDecode(kEs256Y)));

    absl::StatusOr<JwtEcdsaPublicKey> public_key =
        JwtEcdsaPublicKey::Builder()
            .SetPublicPoint(public_point)
            .SetParameters(*params)
            .Build(GetPartialKeyAccess());
    CHECK_OK(public_key);
    absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
        *std::move(public_key),
        RestrictedBigInteger(Base64WebSafeDecode(kEs256S),
                             InsecureSecretKeyAccess::Get()),
        GetPartialKeyAccess());
    CHECK_OK(private_key);

    absl::StatusOr<JwtValidator> test_vector_validator =
        JwtValidatorBuilder()
            .ExpectIssuer("joe")
            .SetFixedNow(absl::FromUnixSeconds(1300819380 - 3600))
            .Build();

    res.push_back(JwtSignatureTestVector{
        /*private_key=*/std::make_shared<JwtEcdsaPrivateKey>(*private_key),
        /*signed_jwt=*/
        // {"alg":"ES256"}
        "eyJhbGciOiJFUzI1NiJ9"
        "."
        // {"iss":"joe",
        //  "exp":1300819380,
        //  "http://example.com/is_root":true}
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        "."
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
        "pmWQxfKTUJqPP3-Kg6NU1Q",
        /*signed_jwt_validator=*/*std::move(test_vector_validator)});
  }
  {
    absl::StatusOr<JwtEcdsaParameters> params = JwtEcdsaParameters::Create(
        JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
        JwtEcdsaParameters::Algorithm::kEs256);
    CHECK_OK(params);
    EcPoint public_point(/*x=*/BigInteger(Base64WebSafeDecode(kEs256X)),
                         /*y=*/BigInteger(Base64WebSafeDecode(kEs256Y)));

    absl::StatusOr<JwtEcdsaPublicKey> public_key =
        JwtEcdsaPublicKey::Builder()
            .SetPublicPoint(public_point)
            .SetParameters(*params)
            .SetIdRequirement(0x01020304)
            .Build(GetPartialKeyAccess());
    CHECK_OK(public_key);
    absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
        *std::move(public_key),
        RestrictedBigInteger(Base64WebSafeDecode(kEs256S),
                             InsecureSecretKeyAccess::Get()),
        GetPartialKeyAccess());
    CHECK_OK(private_key);

    absl::StatusOr<JwtValidator> test_vector_validator =
        JwtValidatorBuilder()
            .ExpectIssuer("issuer")
            .AllowMissingExpiration()
            .Build();

    // Generated with a custom Go script.
    res.push_back(JwtSignatureTestVector{
        /*private_key=*/std::make_shared<JwtEcdsaPrivateKey>(*private_key),
        /*signed_jwt=*/
        // {"kid":"AQIDBA","alg":"ES256"}
        "eyJraWQiOiJBUUlEQkEiLCJhbGciOiJFUzI1NiJ9"
        "."
        // {"iss":"issuer"}
        "eyJpc3MiOiJpc3N1ZXIifQ"
        "."
        "Mgzp130-bvzWJAQlkrQRt45EeKQ6ymZX1ABQoautz1fMW2sVLONkoPl_g6UYxecYz-"
        "2ApvT292dR_3jHd0S3QA",
        /*signed_jwt_validator=*/*std::move(test_vector_validator)});
  }
  {
    absl::StatusOr<JwtEcdsaParameters> params =
        JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kCustom,
                                   JwtEcdsaParameters::Algorithm::kEs256);
    CHECK_OK(params);
    EcPoint public_point(/*x=*/BigInteger(Base64WebSafeDecode(kEs256X)),
                         /*y=*/BigInteger(Base64WebSafeDecode(kEs256Y)));

    absl::StatusOr<JwtEcdsaPublicKey> public_key =
        JwtEcdsaPublicKey::Builder()
            .SetPublicPoint(public_point)
            .SetParameters(*params)
            .SetCustomKid("custom-kid")
            .Build(GetPartialKeyAccess());
    CHECK_OK(public_key);
    absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
        *std::move(public_key),
        RestrictedBigInteger(Base64WebSafeDecode(kEs256S),
                             InsecureSecretKeyAccess::Get()),
        GetPartialKeyAccess());
    CHECK_OK(private_key);

    absl::StatusOr<JwtValidator> test_vector_validator =
        JwtValidatorBuilder()
            .ExpectIssuer("issuer")
            .AllowMissingExpiration()
            .Build();

    // Generated with a custom Go script.
    res.push_back(JwtSignatureTestVector{
        /*private_key=*/std::make_shared<JwtEcdsaPrivateKey>(*private_key),
        /*signed_jwt=*/
        // {"kid":"custom-kid","alg":"ES256"}
        "eyJraWQiOiJjdXN0b20ta2lkIiwiYWxnIjoiRVMyNTYifQ"
        "."
        // {"iss":"issuer"}
        "eyJpc3MiOiJpc3N1ZXIifQ"
        "."
        "A51jqxnj-pddSJUm7dxe4bcmac3xOVg85xhIQ8Fsohv4_"
        "LNMJnmx6Pw9xXGeUHDtW4Y59CxATAmXDqnqvB-kiA",
        /*signed_jwt_validator=*/*std::move(test_vector_validator)});
  }
  {
    absl::StatusOr<JwtRsaSsaPkcs1Parameters> params =
        JwtRsaSsaPkcs1Parameters::Builder()
            .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
            .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
            .SetModulusSizeInBits(size_t(2048))
            .SetPublicExponent(F4())
            .Build();
    CHECK_OK(params);
    absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
        JwtRsaSsaPkcs1PublicKey::Builder()
            .SetModulus(BigInteger(Base64WebSafeDecode(kN2048Base64)))
            .SetParameters(*params)
            .Build(GetPartialKeyAccess());
    CHECK_OK(public_key);
    absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
        JwtRsaSsaPkcs1PrivateKey::Builder()
            .SetPublicKey(*std::move(public_key))
            .SetPrivateExponent(
                RestrictedBigInteger(Base64WebSafeDecode(kD2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetPrimeP(RestrictedBigInteger(Base64WebSafeDecode(kP2048Base64),
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedBigInteger(Base64WebSafeDecode(kQ2048Base64),
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(
                RestrictedBigInteger(Base64WebSafeDecode(kDp2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(
                RestrictedBigInteger(Base64WebSafeDecode(kDq2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(
                RestrictedBigInteger(Base64WebSafeDecode(kQInv2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    CHECK_OK(private_key);

    absl::StatusOr<JwtValidator> test_vector_validator =
        JwtValidatorBuilder()
            .ExpectIssuer("joe")
            .SetFixedNow(absl::FromUnixSeconds(1300819380 - 3600))
            .Build();

    res.push_back(JwtSignatureTestVector{
        /*private_key=*/std::make_shared<JwtRsaSsaPkcs1PrivateKey>(
            *private_key),
        /*signed_jwt=*/
        // {"alg":"RS256"}
        "eyJhbGciOiJSUzI1NiJ9"
        "."
        // {"iss":"joe",
        //  "exp":1300819380,
        //  "http://example.com/is_root":true}
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        "."
        "F_h14Jj1TXhtO6DzWk5Ecei4h7I-"
        "y9aCLUn8wMzFaIQ76MbE5qjkvLGyVpf5zwhrEx8WGmQTjufQ1kIFiu45O9qg0ZnDvRunMi"
        "73F80PxXOdbWIUfY1QF1JCO-TqFHfymG8xShpQEm6R-WeF-"
        "LeWxa6GWaNrJcvM4aggotdGKhgHC7SwYXVYjPhmH4r8jaUuGzCIO_iQb31n-"
        "aR05XR16xti54pIgWlxXNgLhZ13umDeohZ6xkSny4HFvsJ2j08zo1CXtGOPdd34IKv4Y5S"
        "xKJ5YwXVLukyGqvPLy8PNCkQlh32N5kjh9IGdg25OgR08ADQjRKinVjO_UxROv0bj4Q",
        /*signed_jwt_validator=*/*std::move(test_vector_validator)});
  }
  {
    absl::StatusOr<JwtRsaSsaPkcs1Parameters> params =
        JwtRsaSsaPkcs1Parameters::Builder()
            .SetKidStrategy(
                JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
            .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
            .SetModulusSizeInBits(size_t(2048))
            .SetPublicExponent(F4())
            .Build();
    CHECK_OK(params);
    absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
        JwtRsaSsaPkcs1PublicKey::Builder()
            .SetModulus(BigInteger(Base64WebSafeDecode(kN2048Base64)))
            .SetParameters(*params)
            .SetIdRequirement(0x01020304)
            .Build(GetPartialKeyAccess());
    CHECK_OK(public_key);
    absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
        JwtRsaSsaPkcs1PrivateKey::Builder()
            .SetPublicKey(*std::move(public_key))
            .SetPrivateExponent(
                RestrictedBigInteger(Base64WebSafeDecode(kD2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetPrimeP(RestrictedBigInteger(Base64WebSafeDecode(kP2048Base64),
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedBigInteger(Base64WebSafeDecode(kQ2048Base64),
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(
                RestrictedBigInteger(Base64WebSafeDecode(kDp2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(
                RestrictedBigInteger(Base64WebSafeDecode(kDq2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(
                RestrictedBigInteger(Base64WebSafeDecode(kQInv2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    CHECK_OK(private_key);

    absl::StatusOr<JwtValidator> test_vector_validator =
        JwtValidatorBuilder()
            .ExpectIssuer("issuer")
            .AllowMissingExpiration()
            .Build();

    res.push_back(JwtSignatureTestVector{
        /*private_key=*/std::make_shared<JwtRsaSsaPkcs1PrivateKey>(
            *private_key),
        /*signed_jwt=*/
        // {"kid":"AQIDBA","alg":"RS256"}
        "eyJraWQiOiJBUUlEQkEiLCJhbGciOiJSUzI1NiJ9"
        "."
        // {"iss":"issuer"}
        "eyJpc3MiOiJpc3N1ZXIifQ"
        "."
        "SPjCMSIBpUwJZXV-wxs_2IT6Vh6znxtAasbK9eONeljAqPcBDm3dpjC25rtoeWEN5fL1_"
        "P4EG6C87jLQyFgaFt1ghvJIN3_mlcykVKKj1P_wrxIyjg7itRujKw_"
        "GIYj6eT3CV0Ei6xx6UHTkyIGZwQnGO2I6Q9mFyS-1OGBUmK-4xXK_"
        "CCk9Bop5gjNcPkbrnFql15-KygppSbYp8s4ob59K_g6G-b7JN32WAqjoRzaAOJ9GhItg_"
        "2BTow4Z1-4w6wH94X1WRnZbjFXJ6JcBr0noNy1k1PnavsHiQTm_"
        "FRqsR6JbqkVDGLueWHlCBuBFr2SKqvIYDY8DOCP3Qi3nGA",
        /*signed_jwt_validator=*/*std::move(test_vector_validator)});
  }
  {
    absl::StatusOr<JwtRsaSsaPkcs1Parameters> params =
        JwtRsaSsaPkcs1Parameters::Builder()
            .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom)
            .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
            .SetModulusSizeInBits(size_t(2048))
            .SetPublicExponent(F4())
            .Build();
    CHECK_OK(params);
    absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
        JwtRsaSsaPkcs1PublicKey::Builder()
            .SetModulus(BigInteger(Base64WebSafeDecode(kN2048Base64)))
            .SetParameters(*params)
            .SetCustomKid("custom-kid")
            .Build(GetPartialKeyAccess());
    CHECK_OK(public_key);
    absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
        JwtRsaSsaPkcs1PrivateKey::Builder()
            .SetPublicKey(*std::move(public_key))
            .SetPrivateExponent(
                RestrictedBigInteger(Base64WebSafeDecode(kD2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetPrimeP(RestrictedBigInteger(Base64WebSafeDecode(kP2048Base64),
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedBigInteger(Base64WebSafeDecode(kQ2048Base64),
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(
                RestrictedBigInteger(Base64WebSafeDecode(kDp2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(
                RestrictedBigInteger(Base64WebSafeDecode(kDq2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(
                RestrictedBigInteger(Base64WebSafeDecode(kQInv2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    CHECK_OK(private_key);

    absl::StatusOr<JwtValidator> test_vector_validator =
        JwtValidatorBuilder()
            .ExpectIssuer("issuer")
            .AllowMissingExpiration()
            .Build();

    res.push_back(JwtSignatureTestVector{
        /*private_key=*/std::make_shared<JwtRsaSsaPkcs1PrivateKey>(
            *private_key),
        /*signed_jwt=*/
        // {"kid":"custom-kid","alg":"RS256"}
        "eyJraWQiOiJjdXN0b20ta2lkIiwiYWxnIjoiUlMyNTYifQ"
        "."
        // {"iss":"issuer"}
        "eyJpc3MiOiJpc3N1ZXIifQ"
        "."
        "jHc-0csHrSxYdJ6fhfiS88Evy4q1FZ3igL-"
        "f8vP0RBdl5gYy1Lx8qJQJkybZ04BzwyockPz3rs5UGj7a0w5S0jVnPC9Ktg1O5V5vY28ua"
        "EQHXrskuBRPiynNOS_"
        "MCJtc1CJlmzVD99UHJGcKsTfzN30u6wZALnlLqrMEJ6ZluQ4T1UJUJjlFjlrf9qWeHhFu8"
        "xEEovnbwlX54UgGuaYiuqlS1ZV8_c9kG9oXU-8IriuqUctss3VtN4_"
        "1XgEvFreOypKnCn29TAIaB8Frhq5CBsF2O30cTFFa0WtZox2lZsFU9RobrIOELC-"
        "9kpIkE6iS03H-G0fi228XNRNCB0XhzA",
        /*signed_jwt_validator=*/*std::move(test_vector_validator)});
  }
  // RSASSA-PSS.
  {
    absl::StatusOr<JwtRsaSsaPssParameters> params =
        JwtRsaSsaPssParameters::Builder()
            .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
            .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
            .SetModulusSizeInBits(size_t(2048))
            .SetPublicExponent(F4())
            .Build();
    CHECK_OK(params);
    absl::StatusOr<JwtRsaSsaPssPublicKey> public_key =
        JwtRsaSsaPssPublicKey::Builder()
            .SetModulus(BigInteger(Base64WebSafeDecode(kN2048Base64)))
            .SetParameters(*params)
            .Build(GetPartialKeyAccess());
    CHECK_OK(public_key);
    absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key =
        JwtRsaSsaPssPrivateKey::Builder()
            .SetPublicKey(*std::move(public_key))
            .SetPrivateExponent(
                RestrictedBigInteger(Base64WebSafeDecode(kD2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetPrimeP(RestrictedBigInteger(Base64WebSafeDecode(kP2048Base64),
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedBigInteger(Base64WebSafeDecode(kQ2048Base64),
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(
                RestrictedBigInteger(Base64WebSafeDecode(kDp2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(
                RestrictedBigInteger(Base64WebSafeDecode(kDq2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(
                RestrictedBigInteger(Base64WebSafeDecode(kQInv2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    CHECK_OK(private_key);

    absl::StatusOr<JwtValidator> test_vector_validator =
        JwtValidatorBuilder()
            .ExpectIssuer("joe")
            .SetFixedNow(absl::FromUnixSeconds(1300819380 - 3600))
            .Build();

    res.push_back(JwtSignatureTestVector{
        /*private_key=*/std::make_shared<JwtRsaSsaPssPrivateKey>(*private_key),
        /*signed_jwt=*/
        // {"alg":"PS256"}
        "eyJhbGciOiJQUzI1NiJ9"
        "."
        // {"iss":"joe",
        //  "exp":1300819380,
        //  "http://example.com/is_root":true}
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        "."
        "WeMZxYgxDNYFbVm2-pt3uxlj1fIS540KIz1mUMwBfcWunpduvtzj_fWPJv_"
        "bqRC78GdqUaOju01Sega8ECcVsg_8guRyJOl_"
        "BmE9c6kxzSiPyZJ9f1xUjx9WfQ5kcoYMNMVJ_"
        "gUO9QbWin23UiHBBs61rolzn0M6xfNS6MkaYXfsa8aYOWAmsLU_"
        "6WOQtN645bSyoyHDIah2dHXZXQBc6SkqLP8fW1oiTLU4PcVr6SzQIHfK0kS674lqqmdFVK"
        "QfyIakLEhGsQuZ0XzKRE-RbUrQGelKiC1q5Jz3Gq0nAGqOSPkFMA_"
        "5TK1TQhykfbIuXYAClbt1tM74ee27sb2uuQ",
        /*signed_jwt_validator=*/*std::move(test_vector_validator)});
  }
  {
    absl::StatusOr<JwtRsaSsaPssParameters> params =
        JwtRsaSsaPssParameters::Builder()
            .SetKidStrategy(
                JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
            .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
            .SetModulusSizeInBits(size_t(2048))
            .SetPublicExponent(F4())
            .Build();
    CHECK_OK(params);
    absl::StatusOr<JwtRsaSsaPssPublicKey> public_key =
        JwtRsaSsaPssPublicKey::Builder()
            .SetModulus(BigInteger(Base64WebSafeDecode(kN2048Base64)))
            .SetParameters(*params)
            .SetIdRequirement(0x01020304)
            .Build(GetPartialKeyAccess());
    CHECK_OK(public_key);
    absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key =
        JwtRsaSsaPssPrivateKey::Builder()
            .SetPublicKey(*std::move(public_key))
            .SetPrivateExponent(
                RestrictedBigInteger(Base64WebSafeDecode(kD2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetPrimeP(RestrictedBigInteger(Base64WebSafeDecode(kP2048Base64),
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedBigInteger(Base64WebSafeDecode(kQ2048Base64),
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(
                RestrictedBigInteger(Base64WebSafeDecode(kDp2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(
                RestrictedBigInteger(Base64WebSafeDecode(kDq2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(
                RestrictedBigInteger(Base64WebSafeDecode(kQInv2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    CHECK_OK(private_key);

    absl::StatusOr<JwtValidator> test_vector_validator =
        JwtValidatorBuilder()
            .ExpectIssuer("issuer")
            .AllowMissingExpiration()
            .Build();

    res.push_back(JwtSignatureTestVector{
        /*private_key=*/std::make_shared<JwtRsaSsaPssPrivateKey>(*private_key),
        /*signed_jwt=*/
        // {"kid":"AQIDBA","alg":"PS256"}
        "eyJraWQiOiJBUUlEQkEiLCJhbGciOiJQUzI1NiJ9"
        "."
        // {"iss":"issuer"}
        "eyJpc3MiOiJpc3N1ZXIifQ"
        "."
        "g3PZHFG5ZTEhq_"
        "73HvCOy5DMsEIYOvuhDVzx839d8KhepjQ50QukGG5xIndgNkwJ6lHNGoDxXuAWu8ckSkt7"
        "y4RVYc9Qef7cViiHFlJSSFhGocZZuoNFa4uVyQFRe84Zn70kTt2CZ22bhFAJ9rGdTF-"
        "Vw5BgiHquHiivFzHyo6Q4hOL901Sm1hIW3wHJ6wneW_at6iVLv80l3jRxh19y7JfQJ-"
        "hCE3yv5UKDYJMlNwwY1jzVD1GdFwpNnjTtgtSH9rFMY8t7D9iXfQjo4iNpZFxeho2igyuV"
        "dUj8BhfzFO6aSk6NxWdY--ALTJ06YfqMhqNzt_cDrtMksR8vJMcjEQ",
        /*signed_jwt_validator=*/*std::move(test_vector_validator)});
  }
  {
    absl::StatusOr<JwtRsaSsaPssParameters> params =
        JwtRsaSsaPssParameters::Builder()
            .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kCustom)
            .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
            .SetModulusSizeInBits(size_t(2048))
            .SetPublicExponent(F4())
            .Build();
    CHECK_OK(params);
    absl::StatusOr<JwtRsaSsaPssPublicKey> public_key =
        JwtRsaSsaPssPublicKey::Builder()
            .SetModulus(BigInteger(Base64WebSafeDecode(kN2048Base64)))
            .SetParameters(*params)
            .SetCustomKid("custom-kid")
            .Build(GetPartialKeyAccess());
    CHECK_OK(public_key);
    absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key =
        JwtRsaSsaPssPrivateKey::Builder()
            .SetPublicKey(*std::move(public_key))
            .SetPrivateExponent(
                RestrictedBigInteger(Base64WebSafeDecode(kD2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetPrimeP(RestrictedBigInteger(Base64WebSafeDecode(kP2048Base64),
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedBigInteger(Base64WebSafeDecode(kQ2048Base64),
                                            InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(
                RestrictedBigInteger(Base64WebSafeDecode(kDp2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(
                RestrictedBigInteger(Base64WebSafeDecode(kDq2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(
                RestrictedBigInteger(Base64WebSafeDecode(kQInv2048Base64),
                                     InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    CHECK_OK(private_key);

    absl::StatusOr<JwtValidator> test_vector_validator =
        JwtValidatorBuilder()
            .ExpectIssuer("issuer")
            .AllowMissingExpiration()
            .Build();

    res.push_back(JwtSignatureTestVector{
        /*private_key=*/std::make_shared<JwtRsaSsaPssPrivateKey>(*private_key),
        /*signed_jwt=*/
        // {"kid":"custom-kid","alg":"PS256"}
        "eyJraWQiOiJjdXN0b20ta2lkIiwiYWxnIjoiUFMyNTYifQ"
        "."
        // {"iss":"issuer"}
        "eyJpc3MiOiJpc3N1ZXIifQ"
        "."
        "jrJpl_N-"
        "uwEDnFrUoqjvJb0Hc9RCyXl9C8heT9Z7ITKOHn4B8laq3Otz20TLeJ9eHNESHZh7mq5R1o"
        "1vgdkGmxvtmQ8OXC9sr1paFFWREH7FD9ofHSpru7WqkDLH4K9iiQnr6s_"
        "Idy56f9xbELgBkwipSQVeEiLbWXvMasU2YyyOMfEFF40Y-"
        "dzxFVHPUWKV7GdrrT7TdiA9Z9pSl4JNQau3_"
        "sEXOnBZQ3GxJ63vsDQgAzTuz6Ggr8DuuiLHkOZyqAF6qckQ7IzGEYw7jDbHEBR3VbUU8xZ"
        "e-X1uZS-ZbijC452qDAT8qCp0z9zKT-zOOa1W0hdxDOnG2pPWqNzy7g",
        /*signed_jwt_validator=*/*std::move(test_vector_validator)});
  }
  return res;
}

INSTANTIATE_TEST_SUITE_P(JwtDeterministicSignatureTestSuite,
                         JwtDeterministicSignatureTest,
                         testing::ValuesIn(GetJwtSignatureTestVectors()));

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
