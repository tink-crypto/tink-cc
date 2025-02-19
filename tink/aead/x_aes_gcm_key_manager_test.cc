// Copyright 2024 Google LLC
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

#include "tink/aead/x_aes_gcm_key_manager.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/cord.h"
#include "tink/aead.h"
#include "tink/aead/cord_aead.h"
#include "tink/core/key_type_manager.h"
#include "tink/internal/fips_utils.h"
#include "tink/subtle/random.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"
#include "proto/x_aes_gcm.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::FipsCompatibility;
using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyData;
using XAesGcmKeyProto = ::google::crypto::tink::XAesGcmKey;
using ::google::crypto::tink::XAesGcmKeyFormat;
using ::testing::Eq;
using ::testing::Not;

constexpr int kValidKeySize = 32;
constexpr int kMinSaltSize = 8;
constexpr int kMaxSaltSize = 12;

XAesGcmKeyFormat ValidKeyFormat() {
  XAesGcmKeyFormat key_format;
  key_format.mutable_params()->set_salt_size(kMinSaltSize);
  return key_format;
}

XAesGcmKeyProto ValidKey() {
  XAesGcmKeyProto key;
  key.set_version(0);
  key.set_key_value(Random::GetRandomBytes(kValidKeySize));
  key.mutable_params()->set_salt_size(kMinSaltSize);
  return key;
}

TEST(XAesGcmKeyManagerTest, ExpectedKeyMaterialType) {
  EXPECT_THAT(CreateXAesGcmKeyManager()->key_material_type(),
              Eq(KeyData::SYMMETRIC));
}

TEST(XAesGcmKeyManagerTest, ExpectedKeyType) {
  EXPECT_THAT(CreateXAesGcmKeyManager()->get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.XAesGcmKey"));
}

TEST(XAesGcmKeyManagerTest, ExpectedVersion) {
  EXPECT_THAT(CreateXAesGcmKeyManager()->get_version(), Eq(0));
}

TEST(XAesGcmKeyManagerTest, ExpectedFipsStatus) {
  EXPECT_THAT(CreateXAesGcmKeyManager()->FipsStatus(),
              Eq(FipsCompatibility::kNotFips));
}

TEST(XAesGcmKeyManagerTest, DeriveKeyIsUnimplemented) {
  EXPECT_THAT(CreateXAesGcmKeyManager()
                  ->DeriveKey(XAesGcmKeyFormat(),
                              /*input_stream=*/nullptr)
                  .status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(XAesGcmKeyManagerTest, ValidateValidKeyFormat) {
  EXPECT_THAT(CreateXAesGcmKeyManager()->ValidateKeyFormat(ValidKeyFormat()),
              IsOk());
}

TEST(XAesGcmKeyManagerTest, ValidateKeyFormatInvalidVersionFails) {
  XAesGcmKeyFormat key_format = ValidKeyFormat();
  key_format.set_version(1);
  ASSERT_THAT(CreateXAesGcmKeyManager()->ValidateKeyFormat(key_format),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(XAesGcmKeyManagerTest, ValidateKeyFormatWithInvalidSaltSizeFails) {
  std::unique_ptr<XAesGcmKeyManager> key_manager = CreateXAesGcmKeyManager();
  XAesGcmKeyFormat key_format = ValidKeyFormat();
  for (int invalid_salt_size : {7, 13}) {
    key_format.mutable_params()->set_salt_size(invalid_salt_size);
    EXPECT_THAT(key_manager->ValidateKeyFormat(key_format),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(XAesGcmKeyManagerTest, CreateKeyWithInvalidVersionFails) {
  XAesGcmKeyFormat key_format = ValidKeyFormat();
  key_format.set_version(1);
  ASSERT_THAT(CreateXAesGcmKeyManager()->CreateKey(key_format).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(XAesGcmKeyManagerTest, CreateKeyWithInvalidSaltSizeFails) {
  std::unique_ptr<XAesGcmKeyManager> key_manager = CreateXAesGcmKeyManager();
  XAesGcmKeyFormat key_format = ValidKeyFormat();
  for (int invalid_salt_size : {7, 13}) {
    key_format.mutable_params()->set_salt_size(invalid_salt_size);
    EXPECT_THAT(key_manager->CreateKey(key_format).status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(XAesGcmKeyManagerTest, CreateKeyGeneratesRandomKey) {
  std::unique_ptr<XAesGcmKeyManager> key_manager = CreateXAesGcmKeyManager();
  XAesGcmKeyFormat key_format = ValidKeyFormat();

  absl::StatusOr<XAesGcmKeyProto> key_1 = key_manager->CreateKey(key_format);
  ASSERT_THAT(key_1, IsOk());
  absl::StatusOr<XAesGcmKeyProto> key_2 = key_manager->CreateKey(key_format);
  ASSERT_THAT(key_2, IsOk());

  EXPECT_THAT(key_1->key_value(), Not(Eq(key_2->key_value())));
  for (const XAesGcmKeyProto& key : {*key_1, *key_2}) {
    EXPECT_THAT(key.params().salt_size(), Eq(key_format.params().salt_size()));
    EXPECT_THAT(key.version(), Eq(key_manager->get_version()));
  }
}

TEST(XAesGcmKeyManagerTest, CreateKeyWithValidSaltSizes) {
  std::unique_ptr<XAesGcmKeyManager> key_manager = CreateXAesGcmKeyManager();
  XAesGcmKeyFormat key_format = ValidKeyFormat();
  for (int salt_size = kMinSaltSize; salt_size <= kMaxSaltSize; ++salt_size) {
    key_format.mutable_params()->set_salt_size(salt_size);
    absl::StatusOr<XAesGcmKeyProto> key = key_manager->CreateKey(key_format);
    ASSERT_THAT(key, IsOk());
    EXPECT_THAT(key->params().salt_size(), Eq(salt_size));
  }
}

TEST(XAesGcmKeyManagerTest, ValidateKeyWithInvalidVersionFails) {
  XAesGcmKeyProto key = ValidKey();
  key.set_version(1);
  ASSERT_THAT(CreateXAesGcmKeyManager()->ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(XAesGcmKeyManagerTest, ValidateKeyWithInvalidKeySizeFails) {
  std::unique_ptr<XAesGcmKeyManager> key_manager = CreateXAesGcmKeyManager();
  XAesGcmKeyProto key = ValidKey();
  for (int invalid_key_size : {16, 31, 33}) {
    *key.mutable_key_value() = Random::GetRandomBytes(invalid_key_size);
    EXPECT_THAT(key_manager->ValidateKey(key),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(XAesGcmKeyManagerTest, ValidateKeyWithInvalidSaltSizeFails) {
  std::unique_ptr<XAesGcmKeyManager> key_manager = CreateXAesGcmKeyManager();
  XAesGcmKeyProto key = ValidKey();
  for (int invalid_salt_size : {7, 13}) {
    key.mutable_params()->set_salt_size(invalid_salt_size);
    EXPECT_THAT(key_manager->ValidateKey(key),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(XAesGcmKeyManagerTest, ValidateKeyWithValidSaltSizes) {
  std::unique_ptr<XAesGcmKeyManager> key_manager = CreateXAesGcmKeyManager();
  XAesGcmKeyProto key = ValidKey();
  for (int salt_size = kMinSaltSize; salt_size <= kMaxSaltSize; ++salt_size) {
    key.mutable_params()->set_salt_size(salt_size);
    EXPECT_THAT(key_manager->ValidateKey(key), IsOk());
  }
}

TEST(XAesGcmKeyManagerTest, CreatePrimitiveWithInvalidVersionFails) {
  XAesGcmKeyProto key = ValidKey();
  key.set_version(1);
  ASSERT_THAT(CreateXAesGcmKeyManager()->GetPrimitive<CordAead>(key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(XAesGcmKeyManagerTest, CreatePrimitiveFailsWithInvalidKeySize) {
  std::unique_ptr<XAesGcmKeyManager> key_manager = CreateXAesGcmKeyManager();
  XAesGcmKeyProto key = ValidKey();
  for (int invalid_key_size : {16, 31, 33}) {
    *key.mutable_key_value() = Random::GetRandomBytes(invalid_key_size);
    EXPECT_THAT(key_manager->GetPrimitive<CordAead>(key).status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(XAesGcmKeyManagerTest, CreatePrimitiveFailsWithInvalidSaltSize) {
  std::unique_ptr<XAesGcmKeyManager> key_manager = CreateXAesGcmKeyManager();
  XAesGcmKeyProto key = ValidKey();
  for (int invalid_salt_size : {7, 13}) {
    key.mutable_params()->set_salt_size(invalid_salt_size);
    EXPECT_THAT(key_manager->GetPrimitive<CordAead>(key).status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(XAesGcmKeyManagerTest, CreatePrimitiveWithValidSaltSizes) {
  std::unique_ptr<XAesGcmKeyManager> key_manager = CreateXAesGcmKeyManager();
  XAesGcmKeyProto key = ValidKey();
  for (int salt_size = kMinSaltSize; salt_size <= kMaxSaltSize; ++salt_size) {
    key.mutable_params()->set_salt_size(salt_size);
    EXPECT_THAT(key_manager->GetPrimitive<CordAead>(key), IsOk());
  }
}

TEST(XAesGcmKeyManagerTest, CordAndAeadCompatibility) {
  std::unique_ptr<XAesGcmKeyManager> key_manager = CreateXAesGcmKeyManager();
  XAesGcmKeyProto key = ValidKey();
  absl::StatusOr<std::unique_ptr<Aead>> aead =
      key_manager->GetPrimitive<Aead>(key);
  ASSERT_THAT(aead, IsOk());
  absl::StatusOr<std::unique_ptr<CordAead>> cord_aead =
      key_manager->GetPrimitive<CordAead>(key);
  ASSERT_THAT(cord_aead, IsOk());

  // Use a large plaintext (16 KiB) to have cords with potentially multiple
  // nodes.
  std::string plaintext = Random::GetRandomBytes(1 << 14);
  std::string associated_data = "associated_data";
  absl::StatusOr<std::string> aead_ciphertext =
      (*aead)->Encrypt(plaintext, associated_data);
  ASSERT_THAT(aead_ciphertext, IsOk());
  absl::StatusOr<absl::Cord> cord_aead_ciphertext =
      (*cord_aead)->Encrypt(absl::Cord(plaintext), absl::Cord(associated_data));
  ASSERT_THAT(cord_aead_ciphertext, IsOk());

  absl::StatusOr<std::string> aead_plaintext =
      (*aead)->Decrypt(cord_aead_ciphertext->Flatten(), associated_data);
  EXPECT_THAT(aead_plaintext, IsOk());
  EXPECT_THAT(aead_plaintext, IsOkAndHolds(Eq(plaintext)));
  absl::StatusOr<absl::Cord> cord_aead_plaintext =
      (*cord_aead)
          ->Decrypt(absl::Cord(*aead_ciphertext), absl::Cord(associated_data));
  EXPECT_THAT(cord_aead_plaintext, IsOkAndHolds(Eq(absl::Cord(plaintext))));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
