// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/internal/jwt_ml_dsa_signature_config.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/config/global_registry.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/ssl_util.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/keyset_handle.h"
#include "tink/registry.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;

class JwtSignatureConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
    MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(JwtSignatureConfigTest, GetPrimitiveFromJwtMlDsaParameters) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "JWT ML-DSA not supported in FIPS-only mode";
  }
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "JWT ML-DSA requires BoringSSL.";
  }

  ASSERT_THAT(JwtMlDsaSignatureRegister(), IsOk());

  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*parameters,
                                              KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(KeyGenConfigGlobalRegistry());
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> sign =
      (*handle)->GetPrimitive<JwtPublicKeySign>(ConfigGlobalRegistry());
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> verify =
      (*public_handle)
          ->GetPrimitive<JwtPublicKeyVerify>(ConfigGlobalRegistry());
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

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
