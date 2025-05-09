// Copyright 2019 Google LLC
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

#include "tink/aead/kms_envelope_aead.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/config/global_registry.h"
#include "tink/internal/endian.h"
#include "tink/internal/ssl_util.h"
#include "tink/keyset_handle.h"
#include "tink/mac/mac_key_templates.h"
#include "tink/registry.h"
#include "tink/util/fake_kms_client.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::Aead;
using ::crypto::tink::test::DummyAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyTemplate;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::Test;

constexpr int kEncryptedDekPrefixSize = 4;
constexpr absl::string_view kRemoteAeadName = "kms-backed-aead";

class KmsEnvelopeAeadTest : public Test {
 protected:
  void SetUp() override { ASSERT_THAT(AeadConfig::Register(), IsOk()); }
};

TEST_F(KmsEnvelopeAeadTest, EncryptDecryptSucceed) {
  // Use an AES-128-GCM primitive as the remote one.
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                KeyGenConfigGlobalRegistry());
  ASSERT_THAT(keyset_handle, IsOk());
  KeyTemplate dek_template = AeadKeyTemplates::Aes128Eax();
  absl::StatusOr<std::unique_ptr<Aead>> remote_aead =
      (*keyset_handle)
          ->GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry());

  absl::StatusOr<std::unique_ptr<Aead>> envelope_aead =
      KmsEnvelopeAead::New(dek_template, *std::move(remote_aead));
  ASSERT_THAT(envelope_aead, IsOk());

  std::string message = "Some data to encrypt.";
  std::string aad = "Some associated data.";
  absl::StatusOr<std::string> encrypt_result =
      (*envelope_aead)->Encrypt(message, aad);
  ASSERT_THAT(encrypt_result, IsOk());
  absl::StatusOr<std::string> decrypt_result =
      (*envelope_aead)->Decrypt(encrypt_result.value(), aad);
  EXPECT_THAT(decrypt_result, IsOkAndHolds(message));
}

TEST_F(KmsEnvelopeAeadTest, NewFailsIfReamoteAeadIsNull) {
  KeyTemplate dek_template = AeadKeyTemplates::Aes128Eax();
  EXPECT_THAT(
      KmsEnvelopeAead::New(dek_template, /*remote_aead=*/nullptr).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("non-null")));
}

TEST_F(KmsEnvelopeAeadTest, NewFailsIfDekKeyManagerIsNotRegistered) {
  Registry::Reset();
  KeyTemplate dek_template = AeadKeyTemplates::Aes128Eax();
  auto remote_aead = absl::make_unique<DummyAead>(kRemoteAeadName);
  EXPECT_THAT(
      KmsEnvelopeAead::New(dek_template, std::move(remote_aead)).status(),
      StatusIs(absl::StatusCode::kNotFound, HasSubstr("AesEaxKey")));
}

TEST_F(KmsEnvelopeAeadTest, NewFailsIfUsingDekTemplateOfUnsupportedKeyType) {
  KeyTemplate dek_template = MacKeyTemplates::HmacSha256();
  auto remote_aead = absl::make_unique<DummyAead>(kRemoteAeadName);
  EXPECT_THAT(
      KmsEnvelopeAead::New(dek_template, std::move(remote_aead)).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("unsupported key type")));
}

TEST_F(KmsEnvelopeAeadTest, DecryptFailsWithInvalidCiphertextOrAad) {
  KeyTemplate dek_template = AeadKeyTemplates::Aes128Gcm();
  auto remote_aead = absl::make_unique<DummyAead>(kRemoteAeadName);
  absl::StatusOr<std::unique_ptr<Aead>> aead =
      KmsEnvelopeAead::New(dek_template, std::move(remote_aead));
  ASSERT_THAT(aead, IsOk());

  std::string message = "Some data to encrypt.";
  std::string aad = "Some associated data.";
  absl::StatusOr<std::string> encrypt_result = (*aead)->Encrypt(message, aad);
  ASSERT_THAT(encrypt_result, IsOk());
  auto ciphertext = absl::string_view(*encrypt_result);

  // Ciphertext has size zero or smaller than 4 bytes.
  EXPECT_THAT(
      (*aead)->Decrypt(/*ciphertext=*/"", aad).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("too short")));
  EXPECT_THAT(
      (*aead)->Decrypt(/*ciphertext=*/"sh", aad).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("too short")));

  // Ciphertext is smaller than the size of the key.
  const int dek_encrypted_key_size = internal::LoadBigEndian32(
      reinterpret_cast<const uint8_t*>(ciphertext.data()));
  // We leave only key size and key truncated by one.
  EXPECT_THAT(
      (*aead)
          ->Decrypt(ciphertext.substr(0, 4 + dek_encrypted_key_size - 1), aad)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("length of encrypted DEK too large")));

  std::string corrupted_ciphertext = *encrypt_result;
  // Corrupt the serialized DEK.
  corrupted_ciphertext[4] = 'a';
  EXPECT_THAT(
      (*aead)->Decrypt(corrupted_ciphertext, aad).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("invalid")));

  // Wrong associated data.
  EXPECT_THAT((*aead)->Decrypt(ciphertext, "wrong aad").status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("Authentication failed")));

  std::string ciphertextWithHugeEncryptedDekLength =
      "\x88\x88\x88\x88\x88\x88\x88\x88";
  EXPECT_THAT(
      (*aead)->Decrypt(ciphertextWithHugeEncryptedDekLength, "").status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("length of encrypted DEK too large")));
}

TEST_F(KmsEnvelopeAeadTest, DekMaintainsCorrectKeyFormat) {
  KeyTemplate dek_template = AeadKeyTemplates::Aes128Gcm();
  auto kms_remote_aead = absl::make_unique<DummyAead>(kRemoteAeadName);
  absl::StatusOr<std::unique_ptr<Aead>> aead =
      KmsEnvelopeAead::New(dek_template, std::move(kms_remote_aead));
  ASSERT_THAT(aead, IsOk());

  std::string message = "Some data to encrypt.";
  std::string aad = "Some associated data.";
  absl::StatusOr<std::string> ciphertext = (*aead)->Encrypt(message, aad);
  ASSERT_THAT(ciphertext, IsOk());

  // Recover DEK from ciphertext (see
  // https://developers.google.com/tink/wire-format#envelope_encryption).
  auto enc_dek_size = internal::LoadBigEndian32(
      reinterpret_cast<const uint8_t*>(ciphertext->data()));
  DummyAead remote_aead = DummyAead(kRemoteAeadName);
  absl::string_view encrypted_dek =
      absl::string_view(*ciphertext)
          .substr(kEncryptedDekPrefixSize, enc_dek_size);
  absl::StatusOr<std::string> dek_proto_bytes =
      remote_aead.Decrypt(encrypted_dek,
                          /*associated_data=*/"");
  ASSERT_THAT(dek_proto_bytes, IsOk());

  // Check if we can deserialize a GCM key proto from the decrypted DEK.
  google::crypto::tink::AesGcmKey key;
  EXPECT_TRUE(key.ParseFromString(dek_proto_bytes.value()));
  EXPECT_THAT(key.key_value(), SizeIs(16));
}

TEST_F(KmsEnvelopeAeadTest, MultipleEncryptionsProduceDifferentDeks) {
  KeyTemplate dek_template = AeadKeyTemplates::Aes128Gcm();
  auto kms_remote_aead = absl::make_unique<DummyAead>(kRemoteAeadName);
  absl::StatusOr<std::unique_ptr<Aead>> aead =
      KmsEnvelopeAead::New(dek_template, std::move(kms_remote_aead));
  ASSERT_THAT(aead, IsOk());

  std::string message = "Some data to encrypt.";
  std::string aad = "Some associated data.";

  constexpr int kNumIterations = 2;
  std::vector<google::crypto::tink::AesGcmKey> ciphertexts;
  ciphertexts.reserve(kNumIterations);
  for (int i = 0; i < kNumIterations; i++) {
    absl::StatusOr<std::string> ciphertext = (*aead)->Encrypt(message, aad);
    ASSERT_THAT(ciphertext, IsOk());

    auto enc_dek_size = internal::LoadBigEndian32(
        reinterpret_cast<const uint8_t*>(ciphertext->data()));
    DummyAead remote_aead = DummyAead(kRemoteAeadName);
    absl::StatusOr<std::string> dek_proto_bytes = remote_aead.Decrypt(
        ciphertext->substr(kEncryptedDekPrefixSize, enc_dek_size),
        /*associated_data=*/"");
    ASSERT_THAT(dek_proto_bytes, IsOk());

    google::crypto::tink::AesGcmKey key;
    ASSERT_TRUE(key.ParseFromString(dek_proto_bytes.value()));
    ASSERT_THAT(key.key_value(), SizeIs(16));
    ciphertexts.push_back(key);
  }

  for (int i = 0; i < ciphertexts.size() - 1; i++) {
    for (int j = i + 1; j < ciphertexts.size(); j++) {
      EXPECT_THAT(ciphertexts[i].SerializeAsString(),
                  Not(Eq(ciphertexts[j].SerializeAsString())));
    }
  }
}

class KmsEnvelopeAeadDekTemplatesTest
    : public testing::TestWithParam<KeyTemplate> {
  void SetUp() override { ASSERT_THAT(AeadConfig::Register(), IsOk()); }
};

TEST_P(KmsEnvelopeAeadDekTemplatesTest, EncryptDecrypt) {
  // Use an AES-128-GCM primitive as the remote AEAD.
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                KeyGenConfigGlobalRegistry());
  ASSERT_THAT(keyset_handle, IsOk());
  absl::StatusOr<std::unique_ptr<Aead>> remote_aead =
      (*keyset_handle)
          ->GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry());

  KeyTemplate dek_template = GetParam();
  absl::StatusOr<std::unique_ptr<Aead>> envelope_aead =
      KmsEnvelopeAead::New(dek_template, *std::move(remote_aead));
  ASSERT_THAT(envelope_aead, IsOk());

  std::string plaintext = "plaintext";
  std::string associated_data = "associated_data";
  absl::StatusOr<std::string> ciphertext =
      (*envelope_aead)->Encrypt(plaintext, associated_data);
  ASSERT_THAT(ciphertext, IsOk());
  absl::StatusOr<std::string> decrypted =
      (*envelope_aead)->Decrypt(ciphertext.value(), associated_data);
  EXPECT_THAT(decrypted, IsOkAndHolds(plaintext));
}

std::vector<KeyTemplate> GetTestTemplates() {
  std::vector<KeyTemplate> templates = {
    AeadKeyTemplates::Aes128Gcm(),
    AeadKeyTemplates::Aes256Gcm(),
    AeadKeyTemplates::Aes128CtrHmacSha256(),
    AeadKeyTemplates::Aes128Eax(),
    AeadKeyTemplates::Aes128GcmNoPrefix()
  };
  if (internal::IsBoringSsl()) {
    templates.push_back(AeadKeyTemplates::XChaCha20Poly1305());
    templates.push_back(AeadKeyTemplates::Aes256GcmSiv());
  }
  return templates;
}

INSTANTIATE_TEST_SUITE_P(
    KmsEnvelopeAeadDekTemplatesTest, KmsEnvelopeAeadDekTemplatesTest,
    testing::ValuesIn(GetTestTemplates()));

TEST_F(KmsEnvelopeAeadTest, PrimitiveFromTemplateAndFromNewAreCompatible) {
  absl::StatusOr<std::string> kek_uri_result =
      test::FakeKmsClient::CreateFakeKeyUri();
  ASSERT_THAT(kek_uri_result, IsOk());
  std::string kek_uri = *kek_uri_result;
  KeyTemplate dek_template = AeadKeyTemplates::Aes128Gcm();

  // Create a KmsEnvelopeAead primitive from a KmsEnvelopeAeadKey template.
  absl::Status register_status =
      test::FakeKmsClient::RegisterNewClient(kek_uri, /*credentials_path=*/"");
  ASSERT_THAT(register_status, IsOk());
  // Create a KmsEnvelopeAeadKey template.
  KeyTemplate env_template =
      AeadKeyTemplates::KmsEnvelopeAead(kek_uri, dek_template);
  // Get KMS envelope AEAD primitive.
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(env_template, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<Aead>> envelope_aead_from_template =
      (*handle)->GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(envelope_aead_from_template, IsOk());

  // Create a KmsEnvelopeAead primitive form KmsEnvelopeAead::New.
  absl::StatusOr<std::unique_ptr<test::FakeKmsClient>> client =
      test::FakeKmsClient::New(/*key_uri=*/"", /*credentials_path=*/"");
  ASSERT_THAT(client, IsOk());
  absl::StatusOr<std::unique_ptr<Aead>> remote_aead =
      (*client)->GetAead(kek_uri);
  ASSERT_THAT(remote_aead, IsOk());
  // Get KMS envelope AEAD primitive.
  absl::StatusOr<std::unique_ptr<Aead>> envelope_aead_from_new =
      KmsEnvelopeAead::New(dek_template, *std::move(remote_aead));
  ASSERT_THAT(envelope_aead_from_new, IsOk());

  // Check that envelope_aead_from_template and envelope_aead_from_new are the
  // same primitive by encrypting with envelope_aead_from_template and
  // decrypting with envelope_aead_from_new and vice versa.
  std::string plaintext = "plaintext";
  std::string associated_data = "associated_data";
  {
    absl::StatusOr<std::string> ciphertext =
        (*envelope_aead_from_template)->Encrypt(plaintext, associated_data);
    ASSERT_THAT(ciphertext, IsOk());
    absl::StatusOr<std::string> decrypted =
        (*envelope_aead_from_new)->Decrypt(ciphertext.value(), associated_data);
    EXPECT_THAT(decrypted, IsOkAndHolds(plaintext));
  }
  {
    absl::StatusOr<std::string> ciphertext =
        (*envelope_aead_from_new)->Encrypt(plaintext, associated_data);
    ASSERT_THAT(ciphertext, IsOk());
    absl::StatusOr<std::string> decrypted =
        (*envelope_aead_from_template)
            ->Decrypt(ciphertext.value(), associated_data);
    EXPECT_THAT(decrypted, IsOkAndHolds(plaintext));
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
