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

#include "tink/daead/internal/config_2026.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "tink/configuration.h"
#include "tink/daead/aes_siv_key.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/daead/deterministic_aead_key_templates.h"
#include "tink/daead/internal/aes_siv_test_vectors.h"
#include "tink/daead/internal/key_gen_config_2026.h"
#include "tink/deterministic_aead.h"
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
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;

TEST(DeterministicAead2026Test, PrimitiveWrapper) {
  Configuration config;
  ASSERT_THAT(AddDeterministicAead2026(config), IsOk());
  absl::StatusOr<const KeysetWrapperStore*> store =
      ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<DeterministicAead>(), IsOk());
}

TEST(DeterministicAead2026Test, KeyManager) {
  Configuration config;
  ASSERT_THAT(AddDeterministicAead2026(config), IsOk());
  absl::StatusOr<const KeyTypeInfoStore*> store =
      ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddDeterministicAeadKeyGen2026(key_gen_config), IsOk());
  absl::StatusOr<const KeyTypeInfoStore*> key_gen_store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  for (const KeyTypeInfoStore* s : {*store, *key_gen_store}) {
    EXPECT_THAT(s->Get(AesSivKeyManager().get_key_type()), IsOk());
  }
}

TEST(DeterministicAead2026Test, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddDeterministicAeadKeyGen2026(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddDeterministicAead2026(config), IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(DeterministicAeadKeyTemplates::Aes256Siv(),
                                key_gen_config);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      (*handle)->GetPrimitive<DeterministicAead>(config);
  ASSERT_THAT(daead, IsOk());

  std::string plaintext = "plaintext";
  absl::StatusOr<std::string> ciphertext =
      (*daead)->EncryptDeterministically(plaintext, "ad");
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*daead)->DecryptDeterministically(*ciphertext, "ad"),
              IsOkAndHolds(plaintext));
}

TEST(DeterministicAead2026Test, SerializationRegistry) {
  Configuration config;
  ASSERT_THAT(AddDeterministicAead2026(config), IsOk());
  absl::StatusOr<SerializationRegistry*> registry =
      ConfigurationImpl::GetSerializationRegistry(config);
  ASSERT_THAT(registry, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddDeterministicAeadKeyGen2026(key_gen_config), IsOk());
  absl::StatusOr<SerializationRegistry*> key_gen_registry =
      KeyGenConfigurationImpl::GetSerializationRegistry(key_gen_config);
  ASSERT_THAT(key_gen_registry, IsOk());

  const AesSivKey& key = GetAesSivTestVector(/*key_size_in_bytes=*/64,
                                             AesSivParameters::Variant::kTink)
                             .key;
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

TEST(DeterministicAead2026Test, CreateKey) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddDeterministicAeadKeyGen2026(key_gen_config), IsOk());

  const AesSivKey& expected_key =
      GetAesSivTestVector(/*key_size_in_bytes=*/64,
                          AesSivParameters::Variant::kTink)
          .key;
  absl::StatusOr<std::unique_ptr<Key>> key =
      KeyGenConfigurationImpl::CreateKey(expected_key.GetParameters(),
                                         expected_key.GetIdRequirement(),
                                         key_gen_config);
  ASSERT_THAT(key, IsOk());
  EXPECT_EQ((*key)->GetParameters(), expected_key.GetParameters());
  EXPECT_EQ((*key)->GetIdRequirement(), expected_key.GetIdRequirement());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
