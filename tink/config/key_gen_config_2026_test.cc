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

#include "tink/config/key_gen_config_2026.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/signature/ed25519_verify_key_manager.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;

TEST(KeyGenConfig2026Test, KeyManagers) {
  absl::StatusOr<const internal::KeyTypeInfoStore*> store =
      internal::KeyGenConfigurationImpl::GetKeyTypeInfoStore(
          KeyGenConfig2026());
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get(HmacKeyManager().get_key_type()), IsOk());
  // We only check some key managers to verify general registration
  EXPECT_THAT((*store)->Get(AesGcmKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(AesSivKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(HmacPrfKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(Ed25519VerifyKeyManager().get_key_type()), IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
