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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/jwt/internal/jwt_hmac_key_manager.h"
#include "tink/jwt/internal/jwt_mac_key_gen_config_v0.h"
#include "tink/jwt/jwt_key_templates.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyset_handle.h"
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

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
