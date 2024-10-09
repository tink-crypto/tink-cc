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

#include "tink/experimental/pqcrypto/signature/internal/config_v0.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "tink/configuration.h"
#include "tink/experimental/pqcrypto/signature/internal/key_gen_config_v0.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_parameters.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_parameters.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::Not;

SlhDsaParameters GetSlhDsaParameters(SlhDsaParameters::Variant variant) {
  util::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature, variant);
  CHECK_OK(parameters);
  return *parameters;
}

util::StatusOr<MlDsaParameters> GetMlDsaParameters(
    MlDsaParameters::Variant variant) {
  util::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65, variant);
  CHECK_OK(parameters);
  return *parameters;
}

TEST(PqcSignatureConfigV0Test, PrimitiveWrappers) {
  Configuration config;
  ASSERT_THAT(AddPqcSignatureV0(config), IsOk());
  util::StatusOr<const KeysetWrapperStore*> store =
      ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<PublicKeySign>(), IsOk());
  EXPECT_THAT((*store)->Get<PublicKeyVerify>(), IsOk());
}

TEST(PqcSignatureConfigV0Test, SlhDsaGetPrimitiveWorks) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddPqcSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddPqcSignatureV0(config), IsOk());

  util::StatusOr<SlhDsaParameters> parameters =
      GetSlhDsaParameters(SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*parameters, key_gen_config);
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*handle)->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());
}

TEST(PqcSignatureConfigV0Test, SlhDsaSignVerifyWorks) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddPqcSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddPqcSignatureV0(config), IsOk());

  util::StatusOr<SlhDsaParameters> parameters =
      GetSlhDsaParameters(SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*parameters, key_gen_config);
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*handle)->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  util::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
}

TEST(PqcSignatureConfigV0Test, SlhDsaVerifyWithWrongMessageFails) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddPqcSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddPqcSignatureV0(config), IsOk());

  util::StatusOr<SlhDsaParameters> parameters =
      GetSlhDsaParameters(SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*parameters, key_gen_config);
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*handle)->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  util::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, "wrong_data"), Not(IsOk()));
}

TEST(SignatureV0KeyTypesTest, MlDsaGetPrimitiveWorks) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddPqcSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddPqcSignatureV0(config), IsOk());

  util::StatusOr<MlDsaParameters> parameters =
      GetMlDsaParameters(MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*parameters, key_gen_config);
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*handle)->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());
}

TEST(SignatureV0KeyTypesTest, MlDsaSignVerifyWorks) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddPqcSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddPqcSignatureV0(config), IsOk());

  util::StatusOr<MlDsaParameters> parameters =
      GetMlDsaParameters(MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*parameters, key_gen_config);
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*handle)->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  util::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
}

TEST(SignatureV0KeyTypesTest, MlDsaVerifyWithWrongMessageFails) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddPqcSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddPqcSignatureV0(config), IsOk());

  util::StatusOr<MlDsaParameters> parameters =
      GetMlDsaParameters(MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*parameters, key_gen_config);
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*handle)->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  util::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, "wrong_data"), Not(IsOk()));
}

TEST(PqcSignatureConfigV0Test,
     MultipleEntriesKeysetHandleSignVerifyWithSlhDsaPrimaryWorks) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddPqcSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddPqcSignatureV0(config), IsOk());

  util::StatusOr<SlhDsaParameters> slhdsa_parameters =
      GetSlhDsaParameters(SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(slhdsa_parameters, IsOk());

  util::StatusOr<MlDsaParameters> mldsa_parameters =
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

  util::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry1))
                                            .AddEntry(std::move(entry2))
                                            .Build(key_gen_config);
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      handle->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  util::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
}

TEST(PqcSignatureConfigV0Test,
     MultipleEntriesKeysetHandleSignVerifyWithMlDsaPrimaryWorks) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddPqcSignatureKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddPqcSignatureV0(config), IsOk());

  util::StatusOr<SlhDsaParameters> slhdsa_parameters =
      GetSlhDsaParameters(SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(slhdsa_parameters, IsOk());

  util::StatusOr<MlDsaParameters> mldsa_parameters =
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

  util::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry1))
                                            .AddEntry(std::move(entry2))
                                            .Build(key_gen_config);
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      handle->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  util::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());

  std::string data = "data";
  util::StatusOr<std::string> signature = (*sign)->Sign(data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, data), IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
