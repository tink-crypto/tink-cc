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

#include "tink/aead/internal/config_2026.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "tink/aead.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/aes_eax_key_manager.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_siv_key_manager.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/internal/key_gen_config_2026.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/aes_ctr_hmac_aead_test_vectors.h"
#include "tink/aead/internal/testing/aes_eax_test_vectors.h"
#include "tink/aead/internal/testing/aes_gcm_siv_test_vectors.h"
#include "tink/aead/internal/testing/aes_gcm_test_vectors.h"
#include "tink/aead/internal/testing/x_aes_gcm_test_vectors.h"
#include "tink/aead/internal/testing/xchacha20_poly1305_test_vectors.h"
#include "tink/aead/x_aes_gcm_key_manager.h"
#include "tink/aead/x_aes_gcm_parameters.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/configuration.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyset_handle.h"
#include "tink/parameters.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::google::crypto::tink::KeyTemplate;
using ::testing::TestWithParam;
using ::testing::Values;

TEST(Aead2026Test, PrimitiveWrappers) {
  Configuration config;
  ASSERT_THAT(AddAead2026(config), IsOk());
  absl::StatusOr<const KeysetWrapperStore*> store =
      ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<Aead>(), IsOk());
  EXPECT_THAT((*store)->Get<CordAead>(), IsOk());
}

TEST(Aead2026Test, KeyManagers) {
  Configuration config;
  ASSERT_THAT(AddAead2026(config), IsOk());
  absl::StatusOr<const KeyTypeInfoStore*> store =
      ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddAeadKeyGen2026(key_gen_config), IsOk());
  absl::StatusOr<const KeyTypeInfoStore*> key_gen_store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  for (const KeyTypeInfoStore* s : {*store, *key_gen_store}) {
    EXPECT_THAT(s->Get(AesCtrHmacAeadKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(AesEaxKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(AesGcmKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(AesGcmSivKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(CreateXAesGcmKeyManager()->get_key_type()), IsOk());
    EXPECT_THAT(s->Get(XChaCha20Poly1305KeyManager().get_key_type()), IsOk());
  }
}

using Aead2026KeyTypesTest = TestWithParam<KeyTemplate>;
using CordAead2026KeyTypesTest = TestWithParam<KeyTemplate>;
using CordAead2026BoringSslKeyTypesTest = TestWithParam<KeyTemplate>;

INSTANTIATE_TEST_SUITE_P(Aead2026KeyTypesTestSuite, Aead2026KeyTypesTest,
                         Values(AeadKeyTemplates::Aes128CtrHmacSha256(),
                                AeadKeyTemplates::Aes128Eax(),
                                AeadKeyTemplates::Aes128Gcm(),
                                AeadKeyTemplates::Aes128GcmSiv(),
                                AeadKeyTemplates::XChaCha20Poly1305()));
INSTANTIATE_TEST_SUITE_P(CordAead2026KeyTypesTestSuite,
                         CordAead2026KeyTypesTest,
                         Values(AeadKeyTemplates::Aes256Gcm(),
                                AeadKeyTemplates::XAes256Gcm160BitNonce(),
                                AeadKeyTemplates::XAes256Gcm192BitNonce()));
INSTANTIATE_TEST_SUITE_P(CordAead2026BoringSslKeyTypesTestSuite,
                         CordAead2026BoringSslKeyTypesTest,
                         Values(AeadKeyTemplates::Aes128GcmSiv(),
                                AeadKeyTemplates::Aes256GcmSiv()));

TEST_P(Aead2026KeyTypesTest, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddAeadKeyGen2026(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddAead2026(config), IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), key_gen_config);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<Aead>> aead =
      (*handle)->GetPrimitive<Aead>(config);
  ASSERT_THAT(aead, IsOk());

  std::string plaintext = "plaintext";
  absl::StatusOr<std::string> ciphertext = (*aead)->Encrypt(plaintext, "ad");
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, "ad"), IsOkAndHolds(plaintext));
}

TEST_P(CordAead2026KeyTypesTest, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddAeadKeyGen2026(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddAead2026(config), IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), key_gen_config);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<CordAead>> aead =
      (*handle)->GetPrimitive<CordAead>(config);
  ASSERT_THAT(aead, IsOk());

  absl::Cord plaintext("plaintext");
  absl::Cord aad("ad");
  absl::StatusOr<absl::Cord> ciphertext = (*aead)->Encrypt(plaintext, aad);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, aad), IsOkAndHolds(plaintext));
}

TEST_P(CordAead2026BoringSslKeyTypesTest, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddAeadKeyGen2026(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddAead2026(config), IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), key_gen_config);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<CordAead>> aead =
      (*handle)->GetPrimitive<CordAead>(config);
  ASSERT_THAT(aead, IsOk());

  absl::Cord plaintext("plaintext");
  absl::Cord aad("ad");
  absl::StatusOr<absl::Cord> ciphertext = (*aead)->Encrypt(plaintext, aad);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, aad), IsOkAndHolds(plaintext));
}

struct NamedAeadTestVector {
  std::string test_name;
  AeadTestVector vector;
};

using Aead2026SerializationTest = TestWithParam<NamedAeadTestVector>;

INSTANTIATE_TEST_SUITE_P(
    Aead2026SerializationTestSuite, Aead2026SerializationTest,
    Values(
        NamedAeadTestVector{"AesCtrHmacAead",
                            GetAesCtrHmacAeadTestVector(
                                /*aes_key_size_in_bytes=*/16,
                                AesCtrHmacAeadParameters::Variant::kTink)},
        NamedAeadTestVector{"AesEax", GetAesEaxTestVector(
                                          /*key_size_in_bytes=*/16,
                                          AesEaxParameters::Variant::kTink)},
        NamedAeadTestVector{"AesGcm", GetAesGcmTestVector(
                                          /*key_size_in_bytes=*/16,
                                          AesGcmParameters::Variant::kTink)},
        NamedAeadTestVector{
            "AesGcmSiv",
            GetAesGcmSivTestVector(
                /*key_size_in_bytes=*/16, AesGcmSivParameters::Variant::kTink)},
        NamedAeadTestVector{"XAesGcm", GetXAesGcmTestVector(
                                           /*salt_size_in_bytes=*/12,
                                           XAesGcmParameters::Variant::kTink)},
        NamedAeadTestVector{"XChaCha20Poly1305",
                            GetXChaCha20Poly1305TestVector(
                                XChaCha20Poly1305Parameters::Variant::kTink)}),
    [](const testing::TestParamInfo<NamedAeadTestVector>& info) {
      return info.param.test_name;
    });

TEST_P(Aead2026SerializationTest, SerializationRegistry) {
  Configuration config;
  ASSERT_THAT(AddAead2026(config), IsOk());
  absl::StatusOr<SerializationRegistry*> registry =
      ConfigurationImpl::GetSerializationRegistry(config);
  ASSERT_THAT(registry, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddAeadKeyGen2026(key_gen_config), IsOk());
  absl::StatusOr<SerializationRegistry*> key_gen_registry =
      KeyGenConfigurationImpl::GetSerializationRegistry(key_gen_config);
  ASSERT_THAT(key_gen_registry, IsOk());

  const Key& key = *GetParam().vector.aead_key;
  struct NamedRegistry {
    const char* name;
    const SerializationRegistry* registry;
  };
  for (const NamedRegistry& entry :
       {NamedRegistry{"Configuration", *registry},
        NamedRegistry{"KeyGenConfiguration", *key_gen_registry}}) {
    SCOPED_TRACE(entry.name);
    const SerializationRegistry* serialization_registry = entry.registry;
    absl::StatusOr<std::unique_ptr<Serialization>> serialized_params =
        serialization_registry
            ->SerializeParameters<ProtoParametersSerialization>(
                key.GetParameters());
    ASSERT_THAT(serialized_params, IsOk());
    absl::StatusOr<std::unique_ptr<Parameters>> parsed_params =
        serialization_registry->ParseParameters(**serialized_params);
    ASSERT_THAT(parsed_params, IsOk());
    EXPECT_EQ(**parsed_params, key.GetParameters());

    absl::StatusOr<std::unique_ptr<Serialization>> serialized_key =
        serialization_registry->SerializeKey<ProtoKeySerialization>(
            key, InsecureSecretKeyAccess::Get());
    ASSERT_THAT(serialized_key, IsOk());
    absl::StatusOr<std::unique_ptr<Key>> parsed_key =
        serialization_registry->ParseKey(**serialized_key,
                                         InsecureSecretKeyAccess::Get());
    ASSERT_THAT(parsed_key, IsOk());
    EXPECT_EQ(**parsed_key, key);
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
