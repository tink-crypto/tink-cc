// Copyright 2020 Google LLC
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

#include "tink/util/fake_kms_client.h"

#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/config/global_registry.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/kms_aead.pb.h"
#include "proto/kms_envelope.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace test {
namespace {

using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::KmsAeadKeyFormat;
using ::google::crypto::tink::KmsEnvelopeAeadKeyFormat;
using ::google::crypto::tink::OutputPrefixType;
using ::crypto::tink::test::IsOk;
using ::testing::Not;

// TODO(b/174740983) Add this function to aead_key_templates.
KeyTemplate NewKmsAeadKeyTemplate(std::string key_uri) {
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.KmsAeadKey");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  KmsAeadKeyFormat key_format;
  key_format.set_key_uri(key_uri);
  key_format.SerializeToString(key_template.mutable_value());
  return key_template;
}

// TODO(b/174740983) Add this function to aead_key_templates.
KeyTemplate NewKmsEnvelopeKeyTemplate(std::string key_uri,
                                      const KeyTemplate& dek_template) {
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  KmsEnvelopeAeadKeyFormat key_format;
  key_format.set_kek_uri(key_uri);
  key_format.mutable_dek_template()->MergeFrom(dek_template);
  key_format.SerializeToString(key_template.mutable_value());
  return key_template;
}

class FakeKmsClientTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() { ASSERT_THAT(AeadConfig::Register(), IsOk()); }
};

TEST_F(FakeKmsClientTest, CreateNewAeadSuccess) {
  auto uri_result = FakeKmsClient::CreateFakeKeyUri();
  EXPECT_THAT(uri_result, IsOk());
  std::string key_uri = uri_result.value();

  auto client_result = FakeKmsClient::New(key_uri, "");
  ASSERT_THAT(client_result, IsOk());
  auto client = std::move(client_result.value());
  EXPECT_TRUE(client->DoesSupport(key_uri));

  auto aead_result = client->GetAead(key_uri);
  ASSERT_THAT(aead_result, IsOk());
  auto aead = std::move(aead_result.value());

  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";
  auto encrypt_result = aead->Encrypt(plaintext, aad);
  ASSERT_THAT(encrypt_result, IsOk());
  std::string ciphertext = encrypt_result.value();
  auto decrypt_result = aead->Decrypt(ciphertext, aad);
  ASSERT_THAT(decrypt_result, IsOk());
  EXPECT_EQ(plaintext, decrypt_result.value());
}

TEST_F(FakeKmsClientTest, ClientIsBound) {
  std::string key_uri =
      "fake-kms://"
      "CL3oi0kSVwpMCjB0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNF"
      "YXhLZXkSFhICCBAaEPFnQNgtxEG0vEek8bBfgL8YARABGL3oi0kgAQ";
  auto client_result = FakeKmsClient::New(key_uri, "");
  ASSERT_THAT(client_result, IsOk());
  auto client = std::move(client_result.value());

  // No other key_uri is accepted, even a valid one.
  std::string another_key_uri =
      "fake-kms://"
      "CO3y2NgHElgKTAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVz"
      "RWF4S2V5EhYSAggQGhALi4dQMjUR0faRYElRXi__GAEQARjt8tjYByAB";
  EXPECT_FALSE(client->DoesSupport(another_key_uri));
  auto aead_result = client->GetAead(another_key_uri);
  EXPECT_THAT(aead_result, Not(IsOk()));
}

TEST_F(FakeKmsClientTest, ClientIsUnbound) {
  auto client_result = FakeKmsClient::New("", "");
  ASSERT_THAT(client_result, IsOk());
  auto client = std::move(client_result.value());

  // All valid 'fake-kms' key_uris are accepted.
  std::string uri =
      "fake-kms://"
      "CL3oi0kSVwpMCjB0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8udGluay5BZXNF"
      "YXhLZXkSFhICCBAaEPFnQNgtxEG0vEek8bBfgL8YARABGL3oi0kgAQ";
  ASSERT_TRUE(client->DoesSupport(uri));
  auto aead_result = client->GetAead(uri);
  ASSERT_THAT(aead_result, IsOk());

  std::string another_uri =
      "fake-kms://"
      "CO3y2NgHElgKTAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVz"
      "RWF4S2V5EhYSAggQGhALi4dQMjUR0faRYElRXi__GAEQARjt8tjYByAB";
  EXPECT_TRUE(client->DoesSupport(another_uri));
  auto another_aead_result = client->GetAead(another_uri);
  EXPECT_THAT(another_aead_result, IsOk());
}

TEST_F(FakeKmsClientTest, RegisterAndEncryptDecryptWithKmsAead) {
  auto uri_result = FakeKmsClient::CreateFakeKeyUri();
  ASSERT_THAT(uri_result, IsOk());
  std::string key_uri = uri_result.value();
  auto status = FakeKmsClient::RegisterNewClient(key_uri, "");
  EXPECT_THAT(status, IsOk());

  KeyTemplate key_template = NewKmsAeadKeyTemplate(key_uri);
  auto handle_result =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle_result, IsOk());
  auto aead_result = handle_result.value()->GetPrimitive<crypto::tink::Aead>(
      ConfigGlobalRegistry());
  ASSERT_THAT(aead_result, IsOk());
  auto aead = std::move(aead_result.value());

  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";
  auto encrypt_result = aead->Encrypt(plaintext, aad);
  EXPECT_THAT(encrypt_result, IsOk());
  std::string ciphertext = encrypt_result.value();
  auto decrypt_result = aead->Decrypt(ciphertext, aad);
  ASSERT_THAT(decrypt_result, IsOk());
  EXPECT_EQ(plaintext, decrypt_result.value());
}

TEST_F(FakeKmsClientTest, RegisterAndEncryptDecryptWithKmsEnvelopeAead) {
  auto uri_result = FakeKmsClient::CreateFakeKeyUri();
  ASSERT_THAT(uri_result, IsOk());
  std::string key_uri = uri_result.value();
  auto status = FakeKmsClient::RegisterNewClient(key_uri, "");
  ASSERT_THAT(status, IsOk());

  KeyTemplate key_template =
      NewKmsEnvelopeKeyTemplate(key_uri, AeadKeyTemplates::Aes128Gcm());
  auto handle_result =
      KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle_result, IsOk());
  auto aead_result = handle_result.value()->GetPrimitive<crypto::tink::Aead>(
      ConfigGlobalRegistry());
  ASSERT_THAT(aead_result, IsOk());
  auto aead = std::move(aead_result.value());

  std::string plaintext = "some_plaintext";
  std::string aad = "some_aad";
  auto encrypt_result = aead->Encrypt(plaintext, aad);
  ASSERT_THAT(encrypt_result, IsOk());
  std::string ciphertext = encrypt_result.value();
  auto decrypt_result = aead->Decrypt(ciphertext, aad);
  ASSERT_THAT(decrypt_result, IsOk());
  EXPECT_EQ(plaintext, decrypt_result.value());
}

// TODO(b/174740983): Add test where an unbounded KeyClient is registered.
// This is not yet implemented as it would break the isolation of the tests:
// Once a unbounded client is registered, it can't currently be unregistered.

}  // namespace
}  // namespace test
}  // namespace tink
}  // namespace crypto
