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
///////////////////////////////////////////////////////////////////////////////

#include "tink/config/fips_140_2.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_eax_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_siv_key_manager.h"
#include "tink/aead/x_aes_gcm_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/chunked_mac.h"
#include "tink/config/internal/fips_140_2_test_params.h"
#include "tink/config/key_gen_fips_140_2.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_handle_builder.h"
#include "tink/mac.h"
#include "tink/mac/aes_cmac_key_manager.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/prf/aes_cmac_prf_key_manager.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/prf/prf_set.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/ed25519_sign_key_manager.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
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
using ::testing::SizeIs;
using ::testing::TestParamInfo;
using ::testing::ValuesIn;

class Fips1402Test : public ::testing::Test {
 protected:
  void TearDown() override { internal::UnSetFipsRestricted(); }
};

TEST_F(Fips1402Test, PrimitiveWrappers) {
  if (!internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  absl::StatusOr<const internal::KeysetWrapperStore *> store =
      internal::ConfigurationImpl::GetKeysetWrapperStore(ConfigFips140_2());
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<Mac>(), IsOk());
  EXPECT_THAT((*store)->Get<ChunkedMac>(), IsOk());
  EXPECT_THAT((*store)->Get<Aead>(), IsOk());
  EXPECT_THAT((*store)->Get<PrfSet>(), IsOk());
  EXPECT_THAT((*store)->Get<PublicKeySign>(), IsOk());
  EXPECT_THAT((*store)->Get<PublicKeyVerify>(), IsOk());
}

TEST_F(Fips1402Test, KeyManagers) {
  if (!internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  absl::StatusOr<const internal::KeyTypeInfoStore *> store =
      internal::ConfigurationImpl::GetKeyTypeInfoStore(ConfigFips140_2());
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

TEST_F(Fips1402Test, FailsInNonFipsMode) {
  if (internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in non-FIPS mode";
  }

  EXPECT_DEATH_IF_SUPPORTED(
      ConfigFips140_2(), "BoringSSL not built with the BoringCrypto module.");
}

TEST_F(Fips1402Test, NonFipsTypeNotPresent) {
  if (!internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  absl::StatusOr<const internal::KeyTypeInfoStore *> store =
      internal::ConfigurationImpl::GetKeyTypeInfoStore(ConfigFips140_2());
  ASSERT_THAT(store, IsOk());
  EXPECT_THAT((*store)->Get(AesCmacKeyManager().get_key_type()).status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST_F(Fips1402Test, GetPrimitive) {
  if (!internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                KeyGenConfigFips140_2());
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<Aead>> aead =
      (*handle)->GetPrimitive<Aead>(ConfigFips140_2());
  ASSERT_THAT(aead, IsOk());

  std::string plaintext = "plaintext";
  std::string ad = "ad";
  absl::StatusOr<std::string> ciphertext = (*aead)->Encrypt(plaintext, ad);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, ad), IsOkAndHolds(plaintext));
}

std::string TestCaseName(const TestParamInfo<Fips1402TestCase>& info) {
  return info.param.name;
}

// A non-FIPS key generation configuration which supports all the parameters
// in the Denied*Parameters() tables. Must be used with FIPS restrictions
// disabled.
const KeyGenConfiguration& NonFipsKeyGenConfig() {
  static const KeyGenConfiguration* instance = [] {
    KeyGenConfiguration* config = new KeyGenConfiguration();
    // AEAD.
    ABSL_CHECK_OK(internal::KeyGenConfigurationImpl::AddKeyTypeManager(
        std::make_unique<AesGcmSivKeyManager>(), *config));
    ABSL_CHECK_OK(internal::KeyGenConfigurationImpl::AddKeyTypeManager(
        std::make_unique<AesEaxKeyManager>(), *config));
    ABSL_CHECK_OK(internal::KeyGenConfigurationImpl::AddKeyTypeManager(
        std::make_unique<XChaCha20Poly1305KeyManager>(), *config));
    ABSL_CHECK_OK(internal::KeyGenConfigurationImpl::AddKeyTypeManager(
        CreateXAesGcmKeyManager(), *config));
    // MAC.
    ABSL_CHECK_OK(internal::KeyGenConfigurationImpl::AddKeyTypeManager(
        std::make_unique<AesCmacKeyManager>(), *config));
    // PRF.
    ABSL_CHECK_OK(internal::KeyGenConfigurationImpl::AddKeyTypeManager(
        std::make_unique<AesCmacPrfKeyManager>(), *config));
    ABSL_CHECK_OK(internal::KeyGenConfigurationImpl::AddKeyTypeManager(
        std::make_unique<HkdfPrfKeyManager>(), *config));
    // Signature.
    ABSL_CHECK_OK(internal::KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
        std::make_unique<RsaSsaPkcs1SignKeyManager>(),
        std::make_unique<RsaSsaPkcs1VerifyKeyManager>(), *config));
    ABSL_CHECK_OK(internal::KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
        std::make_unique<RsaSsaPssSignKeyManager>(),
        std::make_unique<RsaSsaPssVerifyKeyManager>(), *config));
    ABSL_CHECK_OK(internal::KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
        std::make_unique<Ed25519SignKeyManager>(),
        std::make_unique<Ed25519VerifyKeyManager>(), *config));
    return config;
  }();
  return *instance;
}

// Base fixture for the tests parameterized over the tables in
// internal/fips_140_2_test_params.h.
class Fips1402ParamTest : public ::testing::TestWithParam<Fips1402TestCase> {
 protected:
  void SetUp() override {
    if (!internal::IsFipsEnabledInSsl()) {
      GTEST_SKIP() << "Only test in FIPS mode";
    }
    // TODO(ambrosin): Check if we can do this in KeyGenConfigFips140_2()
    // / ConfigFips140_2(). Without this, generating a keyset from `Parameters`
    // with KeyGenConfigFips140_2() fails with "Failed to serialize legacy proto
    // parameters".
    ASSERT_THAT(internal::RegisterFips1402TestProtoSerializations(), IsOk());
    // ConfigFips140_2() and KeyGenConfigFips140_2() only enable the FIPS
    // restrictions once, when the static configuration is created, while
    // TearDown() disables them. Enable them explicitly for every test.
    internal::SetFipsRestricted();
  }

  void TearDown() override { internal::UnSetFipsRestricted(); }

  // Generates a keyset with a single key with the parameters of the current
  // test case, using `config`.
  absl::StatusOr<KeysetHandle> GenerateKeyset(
      const KeyGenConfiguration& config) {
    return KeysetHandleBuilder()
        .AddEntry(KeysetHandleBuilder::Entry::CreateFromParams(
            GetParam().params, KeyStatus::kEnabled, /*is_primary=*/true))
        .Build(config);
  }

  // Generates a keyset as in GenerateKeyset(), using a non-FIPS key gen config
  // and with FIPS restrictions disabled. This simulates a key which was
  // generated elsewhere (e.g. read from storage).
  absl::StatusOr<KeysetHandle> GenerateNonFipsKeyset() {
    internal::UnSetFipsRestricted();
    absl::StatusOr<KeysetHandle> handle = GenerateKeyset(NonFipsKeyGenConfig());
    internal::SetFipsRestricted();
    return handle;
  }
};

// AEAD.

using Fips1402AeadTest = Fips1402ParamTest;

TEST_P(Fips1402AeadTest, EncryptDecrypt) {
  absl::StatusOr<KeysetHandle> handle = GenerateKeyset(KeyGenConfigFips140_2());
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<Aead>> aead =
      handle->GetPrimitive<Aead>(ConfigFips140_2());
  ASSERT_THAT(aead, IsOk());

  std::string plaintext = "plaintext";
  std::string ad = "ad";
  absl::StatusOr<std::string> ciphertext = (*aead)->Encrypt(plaintext, ad);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, ad), IsOkAndHolds(plaintext));
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, "wrong ad"), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(Fips1402AeadTests, Fips1402AeadTest,
                         ValuesIn(AllowedAeadParameters()), TestCaseName);

using Fips1402DeniedAeadTest = Fips1402ParamTest;

TEST_P(Fips1402DeniedAeadTest, GetPrimitiveFails) {
  absl::StatusOr<KeysetHandle> handle = GenerateNonFipsKeyset();
  ASSERT_THAT(handle, IsOk());
  EXPECT_THAT(handle->GetPrimitive<Aead>(ConfigFips140_2()), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(Fips1402DeniedAeadTests, Fips1402DeniedAeadTest,
                         ValuesIn(DeniedAeadParameters()), TestCaseName);

// MAC.

using Fips1402MacTest = Fips1402ParamTest;

TEST_P(Fips1402MacTest, ComputeVerify) {
  absl::StatusOr<KeysetHandle> handle = GenerateKeyset(KeyGenConfigFips140_2());
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<Mac>> mac =
      handle->GetPrimitive<Mac>(ConfigFips140_2());
  ASSERT_THAT(mac, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> tag = (*mac)->ComputeMac(data);
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT((*mac)->VerifyMac(*tag, data), IsOk());
  EXPECT_THAT((*mac)->VerifyMac(*tag, "wrong data"), Not(IsOk()));
}

TEST_P(Fips1402MacTest, ChunkedComputeVerify) {
  absl::StatusOr<KeysetHandle> handle = GenerateKeyset(KeyGenConfigFips140_2());
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      handle->GetPrimitive<ChunkedMac>(ConfigFips140_2());
  ASSERT_THAT(chunked_mac, IsOk());
  absl::StatusOr<std::unique_ptr<Mac>> mac =
      handle->GetPrimitive<Mac>(ConfigFips140_2());
  ASSERT_THAT(mac, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMacComputation>> computation =
      (*chunked_mac)->CreateComputation();
  ASSERT_THAT(computation, IsOk());
  ASSERT_THAT((*computation)->Update("da"), IsOk());
  ASSERT_THAT((*computation)->Update("ta"), IsOk());
  absl::StatusOr<std::string> tag = (*computation)->ComputeMac();
  ASSERT_THAT(tag, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*chunked_mac)->CreateVerification(*tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update("data"), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), IsOk());
  // The chunked tag is the same as the non-chunked one.
  EXPECT_THAT((*mac)->VerifyMac(*tag, "data"), IsOk());
}

INSTANTIATE_TEST_SUITE_P(Fips1402MacTests, Fips1402MacTest,
                         ValuesIn(AllowedMacParameters()), TestCaseName);

using Fips1402DeniedMacTest = Fips1402ParamTest;

TEST_P(Fips1402DeniedMacTest, GetPrimitiveFails) {
  absl::StatusOr<KeysetHandle> handle = GenerateNonFipsKeyset();
  ASSERT_THAT(handle, IsOk());
  EXPECT_THAT(handle->GetPrimitive<Mac>(ConfigFips140_2()), Not(IsOk()));
  EXPECT_THAT(handle->GetPrimitive<ChunkedMac>(ConfigFips140_2()), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(Fips1402DeniedMacTests, Fips1402DeniedMacTest,
                         ValuesIn(DeniedMacParameters()), TestCaseName);

// PRF.

using Fips1402PrfTest = Fips1402ParamTest;

TEST_P(Fips1402PrfTest, ComputePrimary) {
  absl::StatusOr<KeysetHandle> handle = GenerateKeyset(KeyGenConfigFips140_2());
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<PrfSet>> prf_set =
      handle->GetPrimitive<PrfSet>(ConfigFips140_2());
  ASSERT_THAT(prf_set, IsOk());

  absl::StatusOr<std::string> output =
      (*prf_set)->ComputePrimary("input", /*output_length=*/16);
  ASSERT_THAT(output, IsOk());
  EXPECT_THAT(*output, SizeIs(16));
}

INSTANTIATE_TEST_SUITE_P(Fips1402PrfTests, Fips1402PrfTest,
                         ValuesIn(AllowedPrfParameters()), TestCaseName);

using Fips1402DeniedPrfTest = Fips1402ParamTest;

TEST_P(Fips1402DeniedPrfTest, GetPrimitiveFails) {
  absl::StatusOr<KeysetHandle> handle = GenerateNonFipsKeyset();
  ASSERT_THAT(handle, IsOk());
  EXPECT_THAT(handle->GetPrimitive<PrfSet>(ConfigFips140_2()), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(Fips1402DeniedPrfTests, Fips1402DeniedPrfTest,
                         ValuesIn(DeniedPrfParameters()), TestCaseName);

// Signature.

using Fips1402SignatureTest = Fips1402ParamTest;

TEST_P(Fips1402SignatureTest, SignVerify) {
  absl::StatusOr<KeysetHandle> handle = GenerateKeyset(KeyGenConfigFips140_2());
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      handle->GetPrimitive<PublicKeySign>(ConfigFips140_2());
  ASSERT_THAT(signer, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> signature = (*signer)->Sign(data);
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(KeyGenConfigFips140_2());
  ASSERT_THAT(public_handle, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(ConfigFips140_2());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, data), IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "wrong data"), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(Fips1402SignatureTests, Fips1402SignatureTest,
                         ValuesIn(AllowedSignatureParameters()), TestCaseName);

using Fips1402DeniedSignatureTest = Fips1402ParamTest;

TEST_P(Fips1402DeniedSignatureTest, GetPrimitiveFails) {
  absl::StatusOr<KeysetHandle> handle = GenerateNonFipsKeyset();
  ASSERT_THAT(handle, IsOk());
  internal::UnSetFipsRestricted();
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(NonFipsKeyGenConfig());
  internal::SetFipsRestricted();
  ASSERT_THAT(public_handle, IsOk());

  EXPECT_THAT(handle->GetPrimitive<PublicKeySign>(ConfigFips140_2()),
              Not(IsOk()));
  EXPECT_THAT(
      (*public_handle)->GetPrimitive<PublicKeyVerify>(ConfigFips140_2()),
      Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(Fips1402DeniedSignatureTests,
                         Fips1402DeniedSignatureTest,
                         ValuesIn(DeniedSignatureParameters()), TestCaseName);

}  // namespace
}  // namespace tink
}  // namespace crypto
