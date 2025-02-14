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

#include "tink/jwt/internal/jwt_mac_config_v0.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "tink/configuration.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/jwt/internal/jwt_hmac_key_manager.h"
#include "tink/jwt/internal/jwt_mac_key_gen_config_v0.h"
#include "tink/jwt/jwt_hmac_key.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/jwt/jwt_key_templates.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
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

TEST(JwtMacV0Test, PrimitiveWrappers) {
  Configuration config;
  ASSERT_THAT(AddJwtMacV0(config), IsOk());
  util::StatusOr<const internal::KeysetWrapperStore*> store =
      internal::ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<JwtMac>(), IsOk());
}

TEST(JwtMacV0Test, KeyManagers) {
  Configuration config;
  ASSERT_THAT(AddJwtMacV0(config), IsOk());
  util::StatusOr<const internal::KeyTypeInfoStore*> store =
      internal::ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddJwtMacKeyGenV0(key_gen_config), IsOk());
  util::StatusOr<const internal::KeyTypeInfoStore*> key_gen_store =
      internal::KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  for (const internal::KeyTypeInfoStore* s : {*store, *key_gen_store}) {
    EXPECT_THAT(s->Get(JwtHmacKeyManager().get_key_type()), IsOk());
  }
}

using JwtMacV0KeyTypesTest = TestWithParam<KeyTemplate>;

INSTANTIATE_TEST_SUITE_P(JwtMacV0KeyTypesTestSuite, JwtMacV0KeyTypesTest,
                         Values(RawJwtHs256Template(), RawJwtHs384Template(),
                                RawJwtHs512Template()));

TEST_P(JwtMacV0KeyTypesTest, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddJwtMacKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddJwtMacV0(config), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), key_gen_config);
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<std::unique_ptr<JwtMac>> jwt_mac =
      (*handle)->GetPrimitive<JwtMac>(config);
  ASSERT_THAT(jwt_mac, IsOk());

  absl::Time now = absl::Now();
  util::StatusOr<RawJwt> raw_jwt = RawJwtBuilder()
                                       .SetTypeHeader("typeHeader")
                                       .SetJwtId("id123")
                                       .SetNotBefore(now - absl::Seconds(300))
                                       .SetIssuedAt(now)
                                       .SetExpiration(now + absl::Seconds(300))
                                       .Build();
  ASSERT_THAT(raw_jwt, IsOk());

  util::StatusOr<JwtValidator> validator =
      JwtValidatorBuilder().ExpectTypeHeader("typeHeader").Build();
  ASSERT_THAT(validator, IsOk());

  util::StatusOr<std::string> compact =
      (*jwt_mac)->ComputeMacAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());
  EXPECT_THAT((*jwt_mac)->VerifyMacAndDecode(*compact, *validator), IsOk());
}

// From https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1
constexpr absl::string_view kKey =
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-"
    "1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

struct JwtMacTestParam {
  std::shared_ptr<const Key> key;
  std::string signed_jwt;
  JwtValidator signed_jwt_validator;
};

std::string Base64WebSafeDecode(absl::string_view base64_string) {
  std::string dest;
  CHECK(absl::WebSafeBase64Unescape(base64_string, &dest))
      << "Failed to base64 decode.";

  return dest;
}

std::vector<JwtMacTestParam> GetJwtMacTestParams() {
  std::vector<JwtMacTestParam> res;
  std::string key_bytes = Base64WebSafeDecode(kKey);
  {
    absl::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
        key_bytes.size(), JwtHmacParameters::KidStrategy::kIgnored,
        JwtHmacParameters::Algorithm::kHs256);
    CHECK_OK(params);

    absl::StatusOr<JwtHmacKey> key =
        JwtHmacKey::Builder()
            .SetParameters(*params)
            .SetKeyBytes(
                RestrictedData(key_bytes, InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    CHECK_OK(key);

    util::StatusOr<JwtValidator> test_vector_validator =
        JwtValidatorBuilder()
            .ExpectIssuer("joe")
            .ExpectTypeHeader("JWT")
            .SetFixedNow(absl::FromUnixSeconds(1300819380 - 3600))
            .Build();

    // From https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1
    res.push_back(JwtMacTestParam{
        /*key=*/std::make_shared<JwtHmacKey>(*key),
        /*signed_jwt=*/
        // {"typ":"JWT","alg":"HS256"}
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
        "."
        // {"iss":"joe",
        //  "exp":1300819380,
        //  "http://example.com/is_root":true}
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
        "."
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        /*signed_jwt_validator=*/*std::move(test_vector_validator)});
  }
  {
    absl::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
        key_bytes.size(), JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
        JwtHmacParameters::Algorithm::kHs256);
    CHECK_OK(params);
    absl::StatusOr<JwtHmacKey> key =
        JwtHmacKey::Builder()
            .SetParameters(*params)
            .SetIdRequirement(0x01020304)
            .SetKeyBytes(
                RestrictedData(key_bytes, InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    CHECK_OK(key);

    util::StatusOr<JwtValidator> test_vector_validator =
        JwtValidatorBuilder()
            .ExpectIssuer("issuer")
            .AllowMissingExpiration()
            .Build();

    // Generated.
    res.push_back(JwtMacTestParam{
        /*key=*/std::make_shared<JwtHmacKey>(*key),
        /*signed_jwt=*/
        // {"kid":"AQIDBA","alg":"HS256"}
        "eyJraWQiOiJBUUlEQkEiLCJhbGciOiJIUzI1NiJ9"
        "."
        // {"iss":"issuer"}
        "eyJpc3MiOiJpc3N1ZXIifQ"
        "."
        "LyeYhbBBMFNjdGo_Qz3SXB7QvYbb-i0Onswr5R7zKvg",
        /*signed_jwt_validator=*/*std::move(test_vector_validator)});
  }
  {
    absl::StatusOr<JwtHmacParameters> params = JwtHmacParameters::Create(
        key_bytes.size(), JwtHmacParameters::KidStrategy::kCustom,
        JwtHmacParameters::Algorithm::kHs256);
    CHECK_OK(params);
    absl::StatusOr<JwtHmacKey> key =
        JwtHmacKey::Builder()
            .SetParameters(*params)
            .SetCustomKid("custom-kid")
            .SetKeyBytes(
                RestrictedData(key_bytes, InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    CHECK_OK(key);

    util::StatusOr<JwtValidator> test_vector_validator =
        JwtValidatorBuilder()
            .ExpectIssuer("issuer")
            .AllowMissingExpiration()
            .Build();

    // Generated.
    res.push_back(JwtMacTestParam{
        /*key=*/std::make_shared<JwtHmacKey>(*key),
        /*signed_jwt=*/
        // {"kid":"custom-kid","alg":"HS256"}
        "eyJraWQiOiJjdXN0b20ta2lkIiwiYWxnIjoiSFMyNTYifQ"
        "."
        // {"iss":"issuer"}
        "eyJpc3MiOiJpc3N1ZXIifQ"
        "."
        "9t5toIv2qTXGyaKYPKZO_b40dtVWIYj8sPLXzFhNXk0",
        /*signed_jwt_validator=*/*std::move(test_vector_validator)});
  }
  return res;
}

using JwtMacTest = TestWithParam<JwtMacTestParam>;

TEST_P(JwtMacTest, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddJwtMacKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddJwtMacV0(config), IsOk());

  JwtMacTestParam test_vector = GetParam();

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              test_vector.key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<JwtMac>> mac =
      handle->GetPrimitive<JwtMac>(config);
  ASSERT_THAT(mac, IsOk());

  // Sign and verify a token.
  util::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());
  util::StatusOr<std::string> compact = (*mac)->ComputeMacAndEncode(*raw_jwt);
  ASSERT_THAT(compact, IsOk());
  util::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());
  EXPECT_THAT((*mac)->VerifyMacAndDecode(*compact, *validator), IsOk());

  // Verify the test vector signed JWT with the JWT validator.
  EXPECT_THAT((*mac)->VerifyMacAndDecode(test_vector.signed_jwt,
                                         test_vector.signed_jwt_validator),
              IsOk());
}

INSTANTIATE_TEST_SUITE_P(JwtMacTestSuite, JwtMacTest,
                         testing::ValuesIn(GetJwtMacTestParams()));

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
