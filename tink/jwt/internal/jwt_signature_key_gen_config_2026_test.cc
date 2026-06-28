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

#include "tink/jwt/internal/jwt_signature_key_gen_config_2026.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "absl/status/status_matchers.h"
#include "tink/internal/ssl_util.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyset_handle.h"

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

using ::absl_testing::IsOk;

TEST(JwtMlDsaSignatureKeyGenConfig2026Test, JwtMlDsaCreateKeysetHandleWorks) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "JWT ML-DSA requires BoringSSL.";
  }

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddJwtSignatureKeyGen2026(key_gen_config), IsOk());

  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*parameters,
                                              key_gen_config);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
