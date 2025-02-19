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

#include "tink/signature/internal/config_v0.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#include "tink/signature/internal/key_gen_config_v0.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/signature/internal/testing/ed25519_test_vectors.h"
#include "tink/signature/internal/testing/ml_dsa_test_vectors.h"
#include "tink/signature/internal/testing/rsa_ssa_pkcs1_test_vectors.h"
#include "tink/signature/internal/testing/rsa_ssa_pss_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyTemplate;
using ::testing::Eq;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::Values;

TEST(SignatureV0Test, PrimitiveWrappers) {
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());
  absl::StatusOr<const KeysetWrapperStore*> store =
      ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<PublicKeySign>(), IsOk());
  EXPECT_THAT((*store)->Get<PublicKeyVerify>(), IsOk());
}

TEST(SignatureV0Test, KeyManagers) {
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());
  absl::StatusOr<const KeyTypeInfoStore*> store =
      ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddSignatureKeyGenV0(key_gen_config), IsOk());
  absl::StatusOr<const KeyTypeInfoStore*> key_gen_store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  for (const KeyTypeInfoStore* s : {*store, *key_gen_store}) {
    EXPECT_THAT(s->Get(EcdsaVerifyKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(Ed25519VerifyKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(RsaSsaPkcs1VerifyKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(RsaSsaPssVerifyKeyManager().get_key_type()), IsOk());
  }
}

using SignatureV0KeyTypesTest = TestWithParam<KeyTemplate>;

INSTANTIATE_TEST_SUITE_P(
    SignatureV0KeyTypesTestSuite, SignatureV0KeyTypesTest,
    Values(SignatureKeyTemplates::EcdsaP256(), SignatureKeyTemplates::Ed25519(),
           SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4(),
           SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4()));

TEST_P(SignatureV0KeyTypesTest, GetPrimitiveSignVerify) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), key_gen_config);
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*handle)->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
}

#ifdef OPENSSL_IS_BORINGSSL
SlhDsaParameters GetSlhDsaParameters(SlhDsaParameters::Variant variant) {
  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature, variant);
  CHECK_OK(parameters);
  return *parameters;
}

MlDsaParameters GetMlDsaParameters(MlDsaParameters::Variant variant) {
  absl::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65, variant);
  CHECK_OK(parameters);
  return *parameters;
}

TEST(SignatureConfigV0Test, SlhDsaGetPrimitiveSignVerifyWorks) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());

  absl::StatusOr<SlhDsaParameters> parameters =
      GetSlhDsaParameters(SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*parameters, key_gen_config);
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*handle)->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
}

TEST(SignatureConfigV0Test, SlhDsaVerifyWithWrongMessageFails) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());

  absl::StatusOr<SlhDsaParameters> parameters =
      GetSlhDsaParameters(SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*parameters, key_gen_config);
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*handle)->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, "wrong_data"), Not(IsOk()));
}

TEST(SignatureConfigV0Test, MlDsaGetPrimitiveSignVerifyWorks) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());

  absl::StatusOr<MlDsaParameters> parameters =
      GetMlDsaParameters(MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*parameters, key_gen_config);
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*handle)->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
}

TEST(SignatureConfigV0Test, MlDsaVerifyWithWrongMessageFails) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());

  absl::StatusOr<MlDsaParameters> parameters =
      GetMlDsaParameters(MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*parameters, key_gen_config);
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*handle)->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, "wrong_data"), Not(IsOk()));
}

TEST(SignatureConfigV0Test,
     MultipleEntriesKeysetHandleSignVerifyWithSlhDsaPrimaryWorks) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());

  absl::StatusOr<SlhDsaParameters> slhdsa_parameters =
      GetSlhDsaParameters(SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(slhdsa_parameters, IsOk());

  absl::StatusOr<MlDsaParameters> mldsa_parameters =
      GetMlDsaParameters(MlDsaParameters::Variant::kTink);
  ASSERT_THAT(mldsa_parameters, IsOk());

  KeysetHandleBuilder builder;
  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(*slhdsa_parameters,
                                                           KeyStatus::kEnabled,
                                                           /*is_primary=*/true);
  KeysetHandleBuilder::Entry entry2 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *mldsa_parameters, KeyStatus::kEnabled,
          /*is_primary=*/false);

  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry1))
                                            .AddEntry(std::move(entry2))
                                            .Build(key_gen_config);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      handle->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
}

TEST(SignatureConfigV0Test,
     MultipleEntriesKeysetHandleSignVerifyWithMlDsaPrimaryWorks) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());

  absl::StatusOr<SlhDsaParameters> slhdsa_parameters =
      GetSlhDsaParameters(SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(slhdsa_parameters, IsOk());

  absl::StatusOr<MlDsaParameters> mldsa_parameters =
      GetMlDsaParameters(MlDsaParameters::Variant::kTink);
  ASSERT_THAT(mldsa_parameters, IsOk());

  KeysetHandleBuilder builder;
  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *slhdsa_parameters, KeyStatus::kEnabled,
          /*is_primary=*/false);
  KeysetHandleBuilder::Entry entry2 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(*mldsa_parameters,
                                                           KeyStatus::kEnabled,
                                                           /*is_primary=*/true);

  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry1))
                                            .AddEntry(std::move(entry2))
                                            .Build(key_gen_config);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      handle->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
}
#endif

// TODO(b/372241762) Add similar tests for SLH-DSA.
using DeterministicSignatureTests =
    testing::TestWithParam<internal::SignatureTestVector>;

// If computing the signature is deterministic, we compute and compare.
TEST_P(DeterministicSignatureTests, ComputeSignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              param.signature_private_key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      handle->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign(param.message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT(*signature, Eq(param.signature));
}

TEST_P(DeterministicSignatureTests, VerifySignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddSignatureKeyGenV0(key_gen_config), IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              param.signature_private_key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(param.signature, param.message), IsOk());
}

// Tests that the config allows correct use with randomized signatures.
using RandomizedSignaturesTest =
    testing::TestWithParam<internal::SignatureTestVector>;

// If computing the signature is randomized, we compute and verify.
TEST_P(RandomizedSignaturesTest, ComputeSignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddSignatureKeyGenV0(key_gen_config), IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              param.signature_private_key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      handle->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign(param.message);
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, param.message), IsOk());
}

TEST_P(RandomizedSignaturesTest, VerifySignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddSignatureKeyGenV0(key_gen_config), IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              param.signature_private_key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(param.signature, param.message), IsOk());
}

TEST_P(RandomizedSignaturesTest, VerifyWrongMessageInTestVectorFails) {
  const internal::SignatureTestVector test_vector = GetParam();

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddSignatureV0(config), IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              test_vector.signature_private_key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build(key_gen_config);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      handle->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verifier, IsOk());

  // Sign the message.
  absl::StatusOr<std::string> signature = (*signer)->Sign(test_vector.message);
  ASSERT_THAT(signature, IsOk());

  EXPECT_THAT((*verifier)->Verify(*signature, "wrong_message"),
              testing::Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPkcs1Test, DeterministicSignatureTests,
    testing::ValuesIn(internal::CreateRsaSsaPkcs1TestVectors()));

INSTANTIATE_TEST_SUITE_P(
    Ed25519Test, DeterministicSignatureTests,
    testing::ValuesIn(internal::CreateEd25519TestVectors()));

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPssTest, RandomizedSignaturesTest,
    testing::ValuesIn(internal::CreateRsaSsaPssTestVectors()));

INSTANTIATE_TEST_SUITE_P(EcdsaTest, RandomizedSignaturesTest,
                         testing::ValuesIn(internal::CreateEcdsaTestVectors()));

#ifdef OPENSSL_IS_BORINGSSL
INSTANTIATE_TEST_SUITE_P(MlDsaTest, RandomizedSignaturesTest,
                         testing::ValuesIn(internal::CreateMlDsaTestVectors()));
#endif

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
