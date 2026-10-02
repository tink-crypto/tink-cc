// Copyright 2023 Google LLC
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

#include "tink/config/key_gen_fips_140_2.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/config/internal/fips_140_2_test_params.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_handle_builder.h"
#include "tink/mac/aes_cmac_key_manager.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::AllowedAeadParameters;
using ::crypto::tink::internal::AllowedMacParameters;
using ::crypto::tink::internal::AllowedPrfParameters;
using ::crypto::tink::internal::AllowedSignatureParameters;
using ::crypto::tink::internal::DeniedAeadParameters;
using ::crypto::tink::internal::DeniedMacParameters;
using ::crypto::tink::internal::DeniedPrfParameters;
using ::crypto::tink::internal::DeniedSignatureParameters;
using ::crypto::tink::internal::Fips1402TestCase;
using ::testing::Not;
using ::testing::TestParamInfo;
using ::testing::ValuesIn;

class KeyGenFips1402Test : public testing::Test {
 protected:
  void TearDown() override { internal::UnSetFipsRestricted(); }
};

TEST_F(KeyGenFips1402Test, KeyManagers) {
  if (!internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  absl::StatusOr<const internal::KeyTypeInfoStore *> store =
      internal::KeyGenConfigurationImpl::GetKeyTypeInfoStore(
          KeyGenConfigFips140_2());
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get(HmacKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(AesCtrHmacAeadKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(AesGcmKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(HmacPrfKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(EcdsaVerifyKeyManager().get_key_type()), IsOk());
  EXPECT_THAT((*store)->Get(RsaSsaPssVerifyKeyManager().get_key_type()),
              IsOk());
  EXPECT_THAT((*store)->Get(RsaSsaPkcs1VerifyKeyManager().get_key_type()),
              IsOk());
}

TEST_F(KeyGenFips1402Test, FailsInNonFipsMode) {
  if (internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in non-FIPS mode";
  }

  EXPECT_DEATH_IF_SUPPORTED(
      KeyGenConfigFips140_2(),
      "BoringSSL not built with the BoringCrypto module.");
}

TEST_F(KeyGenFips1402Test, NonFipsTypeNotPresent) {
  if (!internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  absl::StatusOr<const internal::KeyTypeInfoStore *> store =
      internal::KeyGenConfigurationImpl::GetKeyTypeInfoStore(
          KeyGenConfigFips140_2());
  ASSERT_THAT(store, IsOk());
  EXPECT_THAT((*store)->Get(AesCmacKeyManager().get_key_type()).status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST_F(KeyGenFips1402Test, GenerateNewKeysetHandle) {
  if (!internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  EXPECT_THAT(KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                        KeyGenConfigFips140_2()),
              IsOk());
}

std::string TestCaseName(const TestParamInfo<Fips1402TestCase>& info) {
  return info.param.name;
}

// Base fixture for the tests parameterized over the tables in
// internal/fips_140_2_test_params.h.
class KeyGenFips1402ParamTest
    : public testing::TestWithParam<Fips1402TestCase> {
 protected:
  void SetUp() override {
    if (!internal::IsFipsEnabledInSsl()) {
      GTEST_SKIP() << "Only test in FIPS mode";
    }
    // TODO(ambrosin): Remove once KeyGenConfigFips140_2() / ConfigFips140_2()
    // register the proto serializations (or key creators) of the FIPS key
    // types. Without this, generating a keyset from `Parameters` with
    // KeyGenConfigFips140_2() fails with "Failed to serialize legacy proto
    // parameters".
    ASSERT_THAT(internal::RegisterFips1402TestProtoSerializations(), IsOk());
    // KeyGenConfigFips140_2() only enables the FIPS restrictions once, when
    // the static configuration is created, while TearDown() disables them.
    // Enable them explicitly for every test.
    internal::SetFipsRestricted();
  }

  void TearDown() override { internal::UnSetFipsRestricted(); }

  // Generates a keyset with a single key with the parameters of the current
  // test case, using KeyGenConfigFips140_2().
  absl::StatusOr<KeysetHandle> GenerateKeyset() {
    return KeysetHandleBuilder()
        .AddEntry(KeysetHandleBuilder::Entry::CreateFromParams(
            GetParam().params, KeyStatus::kEnabled, /*is_primary=*/true))
        .Build(KeyGenConfigFips140_2());
  }
};

using KeyGenFips1402AllowedTest = KeyGenFips1402ParamTest;

TEST_P(KeyGenFips1402AllowedTest, GenerateKeysetSucceeds) {
  EXPECT_THAT(GenerateKeyset(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(Aead, KeyGenFips1402AllowedTest,
                         ValuesIn(AllowedAeadParameters()), TestCaseName);
INSTANTIATE_TEST_SUITE_P(Mac, KeyGenFips1402AllowedTest,
                         ValuesIn(AllowedMacParameters()), TestCaseName);
INSTANTIATE_TEST_SUITE_P(Prf, KeyGenFips1402AllowedTest,
                         ValuesIn(AllowedPrfParameters()), TestCaseName);
INSTANTIATE_TEST_SUITE_P(Signature, KeyGenFips1402AllowedTest,
                         ValuesIn(AllowedSignatureParameters()), TestCaseName);

using KeyGenFips1402DeniedTest = KeyGenFips1402ParamTest;

TEST_P(KeyGenFips1402DeniedTest, GenerateKeysetFails) {
  EXPECT_THAT(GenerateKeyset(), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(Aead, KeyGenFips1402DeniedTest,
                         ValuesIn(DeniedAeadParameters()), TestCaseName);
INSTANTIATE_TEST_SUITE_P(Mac, KeyGenFips1402DeniedTest,
                         ValuesIn(DeniedMacParameters()), TestCaseName);
INSTANTIATE_TEST_SUITE_P(Prf, KeyGenFips1402DeniedTest,
                         ValuesIn(DeniedPrfParameters()), TestCaseName);
INSTANTIATE_TEST_SUITE_P(Signature, KeyGenFips1402DeniedTest,
                         ValuesIn(DeniedSignatureParameters()), TestCaseName);

}  // namespace
}  // namespace tink
}  // namespace crypto
