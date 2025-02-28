// Copyright 2021 Google LLC
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

#include "tink/hybrid/internal/hpke_private_key_manager.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/btree_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/config/global_registry.h"
#include "tink/hybrid/hpke_config.h"
#include "tink/hybrid/hpke_proto_serialization.h"
#include "tink/hybrid/hybrid_config.h"
#include "tink/hybrid/internal/hpke_encrypt.h"
#include "tink/hybrid/internal/testing/hpke_test_vectors.h"
#include "tink/hybrid/internal/testing/hybrid_test_vectors.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/subtle/hybrid_test_util.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/hpke.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeKeyFormat;
using ::google::crypto::tink::HpkeParams;
using HpkePrivateKeyProto = ::google::crypto::tink::HpkePrivateKey;
using HpkePublicKeyProto = ::google::crypto::tink::HpkePublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::Values;

HpkeKeyFormat CreateKeyFormat(HpkeKem kem, HpkeKdf kdf, HpkeAead aead) {
  HpkeKeyFormat key_format;
  HpkeParams *params = key_format.mutable_params();
  params->set_kem(kem);
  params->set_kdf(kdf);
  params->set_aead(aead);
  return key_format;
}

absl::StatusOr<HpkePrivateKeyProto> CreateKey(HpkeKem kem, HpkeKdf kdf,
                                              HpkeAead aead) {
  return HpkePrivateKeyManager().CreateKey(CreateKeyFormat(kem, kdf, aead));
}

TEST(HpkePrivateKeyManagerTest, BasicAccessors) {
  EXPECT_THAT(HpkePrivateKeyManager().get_version(), Eq(0));
  EXPECT_THAT(HpkePrivateKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(HpkePrivateKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.HpkePrivateKey"));
}

TEST(HpkePrivateKeyManagerTest, ValidateEmptyKeyFormatFails) {
  EXPECT_THAT(HpkePrivateKeyManager().ValidateKeyFormat(HpkeKeyFormat()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyFormatSucceeds) {
  EXPECT_THAT(HpkePrivateKeyManager().ValidateKeyFormat(
                  CreateKeyFormat(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                                  HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM)),
              IsOk());
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyFormatWithInvalidKemFails) {
  EXPECT_THAT(
      HpkePrivateKeyManager().ValidateKeyFormat(CreateKeyFormat(
          HpkeKem::KEM_UNKNOWN, HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM)),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyFormatWithInvalidKdfFails) {
  EXPECT_THAT(HpkePrivateKeyManager().ValidateKeyFormat(
                  CreateKeyFormat(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                                  HpkeKdf::KDF_UNKNOWN, HpkeAead::AES_128_GCM)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyFormatWithInvalidAeadFails) {
  EXPECT_THAT(HpkePrivateKeyManager().ValidateKeyFormat(CreateKeyFormat(
                  HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                  HpkeAead::AEAD_UNKNOWN)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, CreateKeySucceeds) {
  HpkeKeyFormat key_format =
      CreateKeyFormat(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                      HpkeAead::AES_128_GCM);

  absl::StatusOr<HpkePrivateKeyProto> key =
      HpkePrivateKeyManager().CreateKey(key_format);
  ASSERT_THAT(key, IsOk());

  ASSERT_TRUE(key->has_public_key());
  ASSERT_TRUE(key->public_key().has_params());
  EXPECT_THAT(key->public_key().params().kem(), Eq(key_format.params().kem()));
  EXPECT_THAT(key->public_key().params().kdf(), Eq(key_format.params().kdf()));
  EXPECT_THAT(key->public_key().params().aead(),
              Eq(key_format.params().aead()));
  EXPECT_THAT(key->public_key().public_key(), Not(IsEmpty()));
  EXPECT_THAT(key->private_key(), Not(IsEmpty()));
}

TEST(HpkePrivateKeyManagerTest, CreateP256KeySucceeds) {
  HpkeKeyFormat key_format =
      CreateKeyFormat(HpkeKem::DHKEM_P256_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                      HpkeAead::AES_128_GCM);

  absl::StatusOr<HpkePrivateKeyProto> key =
      HpkePrivateKeyManager().CreateKey(key_format);

  ASSERT_THAT(key, IsOk());
  ASSERT_TRUE(key->has_public_key());
  ASSERT_TRUE(key->public_key().has_params());
  EXPECT_THAT(key->public_key().params().kem(), Eq(key_format.params().kem()));
  EXPECT_THAT(key->public_key().params().kdf(), Eq(key_format.params().kdf()));
  EXPECT_THAT(key->public_key().params().aead(),
              Eq(key_format.params().aead()));
  EXPECT_THAT(key->public_key().public_key().size(), Eq(65));
  EXPECT_THAT(key->private_key().size(), Eq(32));

  // Test that all generated keys are unique
  const int number_of_keys = 1000;
  absl::btree_set<std::string> private_keys;
  absl::btree_set<std::string> public_keys;
  for (int i = 0; i < number_of_keys; ++i) {
    absl::StatusOr<HpkePrivateKeyProto> key =
        HpkePrivateKeyManager().CreateKey(key_format);
    ASSERT_THAT(key, IsOk());
    private_keys.insert(std::string(key->private_key()));
    public_keys.insert(key->public_key().public_key());
  }
  EXPECT_THAT(private_keys.size(), Eq(number_of_keys));
  EXPECT_THAT(public_keys.size(), Eq(number_of_keys));
}

TEST(HpkePrivateKeyManagerTest, CreateP384KeySucceeds) {
  HpkeKeyFormat key_format =
      CreateKeyFormat(HpkeKem::DHKEM_P384_HKDF_SHA384, HpkeKdf::HKDF_SHA256,
                      HpkeAead::AES_128_GCM);

  absl::StatusOr<HpkePrivateKeyProto> key =
      HpkePrivateKeyManager().CreateKey(key_format);

  ASSERT_THAT(key, IsOk());
  ASSERT_TRUE(key->has_public_key());
  ASSERT_TRUE(key->public_key().has_params());
  EXPECT_THAT(key->public_key().params().kem(), Eq(key_format.params().kem()));
  EXPECT_THAT(key->public_key().params().kdf(), Eq(key_format.params().kdf()));
  EXPECT_THAT(key->public_key().params().aead(),
              Eq(key_format.params().aead()));
  EXPECT_THAT(key->public_key().public_key().size(), Eq(97));
  EXPECT_THAT(key->private_key().size(), Eq(48));

  // Test that all generated keys are unique
  const int number_of_keys = 1000;
  absl::btree_set<std::string> private_keys;
  absl::btree_set<std::string> public_keys;
  for (int i = 0; i < number_of_keys; ++i) {
    absl::StatusOr<HpkePrivateKeyProto> key =
        HpkePrivateKeyManager().CreateKey(key_format);
    ASSERT_THAT(key, IsOk());
    private_keys.insert(std::string(key->private_key()));
    public_keys.insert(key->public_key().public_key());
  }
  EXPECT_THAT(private_keys.size(), Eq(number_of_keys));
  EXPECT_THAT(public_keys.size(), Eq(number_of_keys));
}

TEST(HpkePrivateKeyManagerTest, CreateP521KeySucceeds) {
  HpkeKeyFormat key_format =
      CreateKeyFormat(HpkeKem::DHKEM_P521_HKDF_SHA512, HpkeKdf::HKDF_SHA256,
                      HpkeAead::AES_128_GCM);

  absl::StatusOr<HpkePrivateKeyProto> key =
      HpkePrivateKeyManager().CreateKey(key_format);

  ASSERT_THAT(key, IsOk());
  ASSERT_TRUE(key->has_public_key());
  ASSERT_TRUE(key->public_key().has_params());
  EXPECT_THAT(key->public_key().params().kem(), Eq(key_format.params().kem()));
  EXPECT_THAT(key->public_key().params().kdf(), Eq(key_format.params().kdf()));
  EXPECT_THAT(key->public_key().params().aead(),
              Eq(key_format.params().aead()));
  EXPECT_THAT(key->public_key().public_key().size(), Eq(133));
  EXPECT_THAT(key->private_key().size(), Eq(66));

  // Test that all generated keys are unique
  const int number_of_keys = 1000;
  absl::btree_set<std::string> private_keys;
  absl::btree_set<std::string> public_keys;
  for (int i = 0; i < number_of_keys; ++i) {
    absl::StatusOr<HpkePrivateKeyProto> key =
        HpkePrivateKeyManager().CreateKey(key_format);
    ASSERT_THAT(key, IsOk());
    private_keys.insert(std::string(key->private_key()));
    public_keys.insert(key->public_key().public_key());
  }
  EXPECT_THAT(private_keys.size(), Eq(number_of_keys));
  EXPECT_THAT(public_keys.size(), Eq(number_of_keys));
}

TEST(HpkePrivateKeyManagerTest, CreateKeyWithInvalidKemFails) {
  HpkeKeyFormat key_format = CreateKeyFormat(
      HpkeKem::KEM_UNKNOWN, HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM);

  ASSERT_THAT(HpkePrivateKeyManager().CreateKey(key_format).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateEmptyKeyFails) {
  EXPECT_THAT(HpkePrivateKeyManager().ValidateKey(HpkePrivateKeyProto()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateKeySucceeds) {
  absl::StatusOr<HpkePrivateKeyProto> key =
      CreateKey(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                HpkeAead::AES_128_GCM);
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(HpkePrivateKeyManager().ValidateKey(*key), IsOk());
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyWithWrongVersionFails) {
  absl::StatusOr<HpkePrivateKeyProto> key =
      CreateKey(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                HpkeAead::AES_128_GCM);
  ASSERT_THAT(key, IsOk());
  key->set_version(1);

  EXPECT_THAT(HpkePrivateKeyManager().ValidateKey(*key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyWithInvalidKemFails) {
  absl::StatusOr<HpkePrivateKeyProto> key =
      CreateKey(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                HpkeAead::AES_128_GCM);
  ASSERT_THAT(key, IsOk());
  key->mutable_public_key()->mutable_params()->set_kem(HpkeKem::KEM_UNKNOWN);

  EXPECT_THAT(HpkePrivateKeyManager().ValidateKey(*key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyWithInvalidKdfFails) {
  absl::StatusOr<HpkePrivateKeyProto> key =
      CreateKey(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::KDF_UNKNOWN,
                HpkeAead::AES_128_GCM);
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(HpkePrivateKeyManager().ValidateKey(*key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyWithInvalidAeadFails) {
  absl::StatusOr<HpkePrivateKeyProto> key =
      CreateKey(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                HpkeAead::AEAD_UNKNOWN);
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(HpkePrivateKeyManager().ValidateKey(*key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, GetPublicKeySucceeds) {
  HpkeKeyFormat key_format =
      CreateKeyFormat(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                      HpkeAead::AES_128_GCM);
  absl::StatusOr<HpkePrivateKeyProto> key =
      HpkePrivateKeyManager().CreateKey(key_format);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<HpkePublicKeyProto> public_key =
      HpkePrivateKeyManager().GetPublicKey(*key);
  ASSERT_THAT(public_key, IsOk());

  ASSERT_TRUE(key->has_public_key());
  ASSERT_TRUE(key->public_key().has_params());
  EXPECT_THAT(public_key->params().kem(), Eq(key_format.params().kem()));
  EXPECT_THAT(public_key->params().kdf(), Eq(key_format.params().kdf()));
  EXPECT_THAT(public_key->params().aead(), Eq(key_format.params().aead()));
  ASSERT_THAT(public_key->public_key(), Not(IsEmpty()));
  EXPECT_THAT(public_key->public_key(), Eq(key->public_key().public_key()));
}

TEST(HpkePrivateKeyManagerTest, GetPublicKeyP256Succeeds) {
  HpkeKeyFormat key_format =
      CreateKeyFormat(HpkeKem::DHKEM_P256_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                      HpkeAead::AES_128_GCM);
  absl::StatusOr<HpkePrivateKeyProto> key =
      HpkePrivateKeyManager().CreateKey(key_format);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<HpkePublicKeyProto> public_key =
      HpkePrivateKeyManager().GetPublicKey(*key);
  ASSERT_THAT(public_key, IsOk());

  ASSERT_TRUE(key->has_public_key());
  ASSERT_TRUE(key->public_key().has_params());
  EXPECT_THAT(public_key->params().kem(), Eq(HpkeKem::DHKEM_P256_HKDF_SHA256));
  EXPECT_THAT(public_key->params().kdf(), Eq(HpkeKdf::HKDF_SHA256));
  EXPECT_THAT(public_key->params().aead(), Eq(HpkeAead::AES_128_GCM));
  ASSERT_THAT(public_key->public_key(), Not(IsEmpty()));
  EXPECT_THAT(public_key->public_key(), Eq(key->public_key().public_key()));
}

TEST(HpkePrivateKeyManagerTest, GetPublicKey384Succeeds) {
  HpkeKeyFormat key_format =
      CreateKeyFormat(HpkeKem::DHKEM_P384_HKDF_SHA384, HpkeKdf::HKDF_SHA256,
                      HpkeAead::AES_128_GCM);
  absl::StatusOr<HpkePrivateKeyProto> key =
      HpkePrivateKeyManager().CreateKey(key_format);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<HpkePublicKeyProto> public_key =
      HpkePrivateKeyManager().GetPublicKey(*key);
  ASSERT_THAT(public_key, IsOk());

  ASSERT_TRUE(key->has_public_key());
  ASSERT_TRUE(key->public_key().has_params());
  EXPECT_THAT(public_key->params().kem(), Eq(HpkeKem::DHKEM_P384_HKDF_SHA384));
  EXPECT_THAT(public_key->params().kdf(), Eq(HpkeKdf::HKDF_SHA256));
  EXPECT_THAT(public_key->params().aead(), Eq(HpkeAead::AES_128_GCM));
  ASSERT_THAT(public_key->public_key(), Not(IsEmpty()));
  EXPECT_THAT(public_key->public_key(), Eq(key->public_key().public_key()));
}

TEST(HpkePrivateKeyManagerTest, GetPublicKey521Succeeds) {
  HpkeKeyFormat key_format =
      CreateKeyFormat(HpkeKem::DHKEM_P521_HKDF_SHA512, HpkeKdf::HKDF_SHA256,
                      HpkeAead::AES_128_GCM);
  absl::StatusOr<HpkePrivateKeyProto> key =
      HpkePrivateKeyManager().CreateKey(key_format);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<HpkePublicKeyProto> public_key =
      HpkePrivateKeyManager().GetPublicKey(*key);
  ASSERT_THAT(public_key, IsOk());

  ASSERT_TRUE(key->has_public_key());
  ASSERT_TRUE(key->public_key().has_params());
  EXPECT_THAT(public_key->params().kem(), Eq(HpkeKem::DHKEM_P521_HKDF_SHA512));
  EXPECT_THAT(public_key->params().kdf(), Eq(HpkeKdf::HKDF_SHA256));
  EXPECT_THAT(public_key->params().aead(), Eq(HpkeAead::AES_128_GCM));
  ASSERT_THAT(public_key->public_key(), Not(IsEmpty()));
  EXPECT_THAT(public_key->public_key(), Eq(key->public_key().public_key()));
}

using HpkePrivateKeyManagerTest = TestWithParam<HpkeKem>;

INSTANTIATE_TEST_SUITE_P(HpkePrivateKeyManagerTestSuite,
                         HpkePrivateKeyManagerTest,
                         Values(HpkeKem::DHKEM_P256_HKDF_SHA256,
                                HpkeKem::DHKEM_X25519_HKDF_SHA256));

TEST_P(HpkePrivateKeyManagerTest, EncryptThenDecryptSucceeds) {
  HpkeKem kem = GetParam();
  absl::StatusOr<HpkePrivateKeyProto> private_key =
      CreateKey(kem, HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM);
  ASSERT_THAT(private_key, IsOk());
  absl::StatusOr<HpkePublicKeyProto> public_key =
      HpkePrivateKeyManager().GetPublicKey(*private_key);
  ASSERT_THAT(public_key, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      HpkePrivateKeyManager().GetPrimitive<HybridDecrypt>(*private_key);
  ASSERT_THAT(decrypt, IsOk());
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      HpkeEncrypt::New(*public_key);
  ASSERT_THAT(encrypt, IsOk());

  ASSERT_THAT(HybridEncryptThenDecrypt(encrypt->get(), decrypt->get(),
                                       "some text", "some aad"),
              IsOk());
}

TEST(HpkePrivateKeyManagerTest, GetPrimitiveP384Fails) {
  absl::StatusOr<HpkePrivateKeyProto> private_key =
      CreateKey(HpkeKem::DHKEM_P384_HKDF_SHA384, HpkeKdf::HKDF_SHA256,
                HpkeAead::AES_128_GCM);
  ASSERT_THAT(private_key, IsOk());
  absl::StatusOr<HpkePublicKeyProto> public_key =
      HpkePrivateKeyManager().GetPublicKey(*private_key);
  ASSERT_THAT(public_key, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      HpkePrivateKeyManager().GetPrimitive<HybridDecrypt>(*private_key);
  ASSERT_THAT(decrypt.status(), StatusIs(absl::StatusCode::kInvalidArgument));
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      HpkeEncrypt::New(*public_key);
  ASSERT_THAT(encrypt.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, GetPrimitiveP521Fails) {
  absl::StatusOr<HpkePrivateKeyProto> private_key =
      CreateKey(HpkeKem::DHKEM_P521_HKDF_SHA512, HpkeKdf::HKDF_SHA256,
                HpkeAead::AES_128_GCM);
  ASSERT_THAT(private_key, IsOk());
  absl::StatusOr<HpkePublicKeyProto> public_key =
      HpkePrivateKeyManager().GetPublicKey(*private_key);
  ASSERT_THAT(public_key, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      HpkePrivateKeyManager().GetPrimitive<HybridDecrypt>(*private_key);
  ASSERT_THAT(decrypt.status(), StatusIs(absl::StatusCode::kInvalidArgument));
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      HpkeEncrypt::New(*public_key);
  ASSERT_THAT(encrypt.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, EncryptThenDecryptWithDifferentKeysFails) {
  absl::StatusOr<HpkePrivateKeyProto> private_key =
      CreateKey(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                HpkeAead::AES_128_GCM);
  ASSERT_THAT(private_key, IsOk());
  absl::StatusOr<HpkePrivateKeyProto> different_private_key =
      CreateKey(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                HpkeAead::AES_128_GCM);
  ASSERT_THAT(different_private_key, IsOk());
  absl::StatusOr<HpkePublicKeyProto> public_key =
      HpkePrivateKeyManager().GetPublicKey(*different_private_key);
  ASSERT_THAT(public_key, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      HpkePrivateKeyManager().GetPrimitive<HybridDecrypt>(*private_key);
  ASSERT_THAT(decrypt, IsOk());
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      HpkeEncrypt::New(*public_key);
  ASSERT_THAT(encrypt, IsOk());

  ASSERT_THAT(HybridEncryptThenDecrypt(encrypt->get(), decrypt->get(),
                                       "some text", "some aad"),
              Not(IsOk()));
}

using HpkeTestVectorTest = TestWithParam<HybridTestVector>;

TEST_P(HpkeTestVectorTest, DecryptWorks) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterHpke(), IsOk());
  const HybridTestVector& param = GetParam();
  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              param.hybrid_private_key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypter =
      handle->GetPrimitive<HybridDecrypt>(ConfigGlobalRegistry());
  ASSERT_THAT(decrypter, IsOk());
  EXPECT_THAT((*decrypter)->Decrypt(param.ciphertext, param.context_info),
              IsOkAndHolds(Eq(param.plaintext)));
}

TEST_P(HpkeTestVectorTest, DecryptDifferentContextInfoFails) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterHpke(), IsOk());
  const HybridTestVector& param = GetParam();
  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              param.hybrid_private_key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypter =
      handle->GetPrimitive<HybridDecrypt>(ConfigGlobalRegistry());
  ASSERT_THAT(decrypter, IsOk());
  EXPECT_THAT(
      (*decrypter)
          ->Decrypt(param.ciphertext, absl::StrCat(param.context_info, "x")),
      Not(IsOk()));
}

TEST_P(HpkeTestVectorTest, EncryptThenDecryptWorks) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterHpke(), IsOk());
  const HybridTestVector& param = GetParam();
  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              param.hybrid_private_key, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypter =
      handle->GetPrimitive<HybridDecrypt>(ConfigGlobalRegistry());
  ASSERT_THAT(decrypter, IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(KeyGenConfigGlobalRegistry());
  ASSERT_THAT(public_handle, IsOk());
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypter =
      (*public_handle)->GetPrimitive<HybridEncrypt>(ConfigGlobalRegistry());
  ASSERT_THAT(encrypter, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*encrypter)->Encrypt(param.plaintext, param.context_info);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*decrypter)->Decrypt(*ciphertext, param.context_info),
              IsOkAndHolds(Eq(param.plaintext)));
}

INSTANTIATE_TEST_SUITE_P(HpkeTestVectorTest, HpkeTestVectorTest,
                         testing::ValuesIn(CreateHpkeTestVectors()));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
