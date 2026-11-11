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
///////////////////////////////////////////////////////////////////////////////

#include "tink/internal/testing/test_only_key_managers.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/aead/aead_wrapper.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/testing/test_only_key.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyset_handle.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/public_key_sign_wrapper.h"
#include "tink/signature/public_key_verify_wrapper.h"
#include "proto/test_only_key.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::TestOnlyKey;
using ::google::crypto::tink::TestOnlyKeyFormat;
using ::google::crypto::tink::TestOnlyPrivateKey;
using ::google::crypto::tink::TestOnlyPublicKey;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

TEST(TestOnlyKeyTemplatesTest, KeyTemplates) {
  TestOnlyKeyFormat key_format;
  key_format.set_key_size(kTestOnlyKeySizeInBytes);

  KeyTemplate key_template = TestOnlyKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kTestOnlyKeyTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(), Eq(OutputPrefixType::TINK));
  EXPECT_THAT(key_template.value(), Eq(key_format.SerializeAsString()));

  KeyTemplate private_key_template =
      TestOnlyPrivateKeyTemplate(OutputPrefixType::RAW);
  EXPECT_THAT(private_key_template.type_url(), Eq(kTestOnlyPrivateKeyTypeUrl));
  EXPECT_THAT(private_key_template.output_prefix_type(),
              Eq(OutputPrefixType::RAW));
  EXPECT_THAT(private_key_template.value(), Eq(key_format.SerializeAsString()));
}

TEST(TestOnlyKeyTypeManagerTest, CreateKey) {
  TestOnlyKeyFormat key_format;
  key_format.set_key_size(kTestOnlyKeySizeInBytes);

  absl::StatusOr<TestOnlyKey> key =
      TestOnlyKeyTypeManager().CreateKey(key_format);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->version(), Eq(0));
  EXPECT_THAT(key->key_value(), SizeIs(kTestOnlyKeySizeInBytes));
  EXPECT_THAT(TestOnlyKeyTypeManager().ValidateKey(*key), IsOk());
}

TEST(TestOnlyKeyTypeManagerTest, ValidateInvalidKeyAndKeyFormatFails) {
  TestOnlyKey key;
  key.set_version(1);
  key.set_key_value("key");
  TestOnlyKeyFormat key_format;
  key_format.set_key_size(0);

  EXPECT_THAT(TestOnlyKeyTypeManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(TestOnlyKeyTypeManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

TEST(TestOnlyKeyTypeManagerTest, GeneratesUsableKeys) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddKeyTypeManager(
                  std::make_unique<TestOnlyKeyTypeManager>(), key_gen_config),
              IsOk());
  Configuration config;
  ASSERT_THAT(ConfigurationImpl::AddPrimitiveWrapper(
                  std::make_unique<AeadWrapper>(), config),
              IsOk());
  ASSERT_THAT(ConfigurationImpl::AddKeyTypeManager(
                  std::make_unique<TestOnlyKeyTypeManager>(), config),
              IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(TestOnlyKeyTemplate(OutputPrefixType::RAW),
                                key_gen_config);
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<Aead>> aead =
      (*handle)->GetPrimitive<Aead>(config);
  ASSERT_THAT(aead, IsOk());
  absl::StatusOr<std::string> ciphertext = (*aead)->Encrypt("plaintext", "ad");
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, "ad"), IsOkAndHolds("plaintext"));
}

TEST(TestOnlyPrivateKeyTypeManagerTest, CreateKeyAndGetPublicKey) {
  TestOnlyKeyFormat key_format;
  key_format.set_key_size(kTestOnlyKeySizeInBytes);

  absl::StatusOr<TestOnlyPrivateKey> private_key =
      TestOnlyPrivateKeyTypeManager().CreateKey(key_format);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->version(), Eq(0));
  EXPECT_THAT(private_key->key_value(), SizeIs(kTestOnlyKeySizeInBytes));
  EXPECT_THAT(TestOnlyPrivateKeyTypeManager().ValidateKey(*private_key),
              IsOk());

  absl::StatusOr<TestOnlyPublicKey> public_key =
      TestOnlyPrivateKeyTypeManager().GetPublicKey(*private_key);
  ASSERT_THAT(public_key, IsOk());
  EXPECT_THAT(public_key->version(), Eq(0));
  EXPECT_THAT(public_key->key_value(),
              Eq(std::string(private_key->key_value().rbegin(),
                             private_key->key_value().rend())));
  EXPECT_THAT(TestOnlyPublicKeyTypeManager().ValidateKey(*public_key), IsOk());
}

TEST(TestOnlyPrivateKeyTypeManagerTest, ValidateInvalidKeysFails) {
  TestOnlyPrivateKey private_key;
  private_key.set_key_value("ab");
  private_key.mutable_public_key()->set_key_value("ba");
  ASSERT_THAT(TestOnlyPrivateKeyTypeManager().ValidateKey(private_key), IsOk());

  TestOnlyPrivateKey wrong_version = private_key;
  wrong_version.set_version(1);
  TestOnlyPrivateKey wrong_public_key_version = private_key;
  wrong_public_key_version.mutable_public_key()->set_version(1);
  TestOnlyPrivateKey wrong_public_key = private_key;
  wrong_public_key.mutable_public_key()->set_key_value("ab");

  EXPECT_THAT(TestOnlyPrivateKeyTypeManager().ValidateKey(wrong_version),
              Not(IsOk()));
  EXPECT_THAT(
      TestOnlyPrivateKeyTypeManager().ValidateKey(wrong_public_key_version),
      Not(IsOk()));
  EXPECT_THAT(TestOnlyPrivateKeyTypeManager().ValidateKey(wrong_public_key),
              Not(IsOk()));
  EXPECT_THAT(TestOnlyPublicKeyTypeManager().ValidateKey(
                  wrong_public_key_version.public_key()),
              Not(IsOk()));
}

TEST(TestOnlyPrivateKeyTypeManagerTest,
     PublicKeyVerifiesSignaturesOfPrivateKey) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(
      KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
          std::make_unique<TestOnlyPrivateKeyTypeManager>(),
          std::make_unique<TestOnlyPublicKeyTypeManager>(), key_gen_config),
      IsOk());
  Configuration config;
  ASSERT_THAT(ConfigurationImpl::AddPrimitiveWrapper(
                  std::make_unique<PublicKeySignWrapper>(), config),
              IsOk());
  ASSERT_THAT(ConfigurationImpl::AddPrimitiveWrapper(
                  std::make_unique<PublicKeyVerifyWrapper>(), config),
              IsOk());
  ASSERT_THAT(ConfigurationImpl::AddAsymmetricKeyManagers(
                  std::make_unique<TestOnlyPrivateKeyTypeManager>(),
                  std::make_unique<TestOnlyPublicKeyTypeManager>(), config),
              IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> private_handle =
      KeysetHandle::GenerateNew(
          TestOnlyPrivateKeyTemplate(OutputPrefixType::RAW), key_gen_config);
  ASSERT_THAT(private_handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*private_handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      (*private_handle)->GetPrimitive<PublicKeySign>(config);
  ASSERT_THAT(sign, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verify =
      (*public_handle)->GetPrimitive<PublicKeyVerify>(config);
  ASSERT_THAT(verify, IsOk());
  absl::StatusOr<std::string> signature = (*sign)->Sign("data");
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, "data"), IsOk());
  EXPECT_THAT((*verify)->Verify(*signature, "other data"), Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
