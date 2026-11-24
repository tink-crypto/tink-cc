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

#include "tink/prf/internal/config_2026.h"

#include <cstddef>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
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
#include "tink/prf/aes_cmac_prf_key_manager.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/prf/internal/aes_cmac_prf_test_vectors.h"
#include "tink/prf/internal/hkdf_prf_test_vectors.h"
#include "tink/prf/internal/hmac_prf_test_vectors.h"
#include "tink/prf/internal/key_gen_config_2026.h"
#include "tink/prf/prf_key_templates.h"
#include "tink/prf/prf_set.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::google::crypto::tink::KeyTemplate;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::Values;

TEST(Prf2026Test, PrimitiveWrapper) {
  Configuration config;
  ASSERT_THAT(AddPrf2026(config), IsOk());
  absl::StatusOr<const KeysetWrapperStore*> store =
      ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<PrfSet>(), IsOk());
}

TEST(Prf2026Test, KeyManagers) {
  Configuration config;
  ASSERT_THAT(AddPrf2026(config), IsOk());
  absl::StatusOr<const KeyTypeInfoStore*> store =
      ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddPrfKeyGen2026(key_gen_config), IsOk());
  absl::StatusOr<const KeyTypeInfoStore*> key_gen_store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  for (const KeyTypeInfoStore* s : {*store, *key_gen_store}) {
    EXPECT_THAT(s->Get(AesCmacPrfKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(HkdfPrfKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(HmacPrfKeyManager().get_key_type()), IsOk());
  }
}

using Prf2026KeyTypesTest = TestWithParam<KeyTemplate>;

INSTANTIATE_TEST_SUITE_P(Prf2026KeyTypesTestSuite, Prf2026KeyTypesTest,
                         Values(PrfKeyTemplates::AesCmac(),
                                PrfKeyTemplates::HkdfSha256(),
                                PrfKeyTemplates::HmacSha256()));

TEST_P(Prf2026KeyTypesTest, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddPrfKeyGen2026(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddPrf2026(config), IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), key_gen_config);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<PrfSet>> prf =
      (*handle)->GetPrimitive<PrfSet>(config);
  ASSERT_THAT(prf, IsOk());

  size_t output_length = 16;
  absl::StatusOr<std::string> output =
      (*prf)->ComputePrimary("input", output_length);
  ASSERT_THAT(output, IsOk());
  EXPECT_THAT((*output).length(), Eq(output_length));
}

struct NamedKey {
  std::string test_name;
  const Key* key;
};

using Prf2026SerializationTest = TestWithParam<NamedKey>;

INSTANTIATE_TEST_SUITE_P(
    Prf2026SerializationTestSuite, Prf2026SerializationTest,
    Values(NamedKey{"AesCmac",
                    &GetAesCmacPrfTestVector(/*key_size_in_bytes=*/32).key},
           NamedKey{"Hkdf", &GetHkdfPrfTestVector(
                                 /*key_size_in_bytes=*/22,
                                 HkdfPrfParameters::HashType::kSha256)
                                 .key},
           NamedKey{"Hmac", &GetHmacPrfTestVector(
                                 /*key_size_in_bytes=*/40,
                                 HmacPrfParameters::HashType::kSha256)
                                 .key}),
    [](const testing::TestParamInfo<NamedKey>& info) {
      return info.param.test_name;
    });

TEST_P(Prf2026SerializationTest, SerializationRegistry) {
  Configuration config;
  ASSERT_THAT(AddPrf2026(config), IsOk());
  absl::StatusOr<SerializationRegistry*> registry =
      ConfigurationImpl::GetSerializationRegistry(config);
  ASSERT_THAT(registry, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddPrfKeyGen2026(key_gen_config), IsOk());
  absl::StatusOr<SerializationRegistry*> key_gen_registry =
      KeyGenConfigurationImpl::GetSerializationRegistry(key_gen_config);
  ASSERT_THAT(key_gen_registry, IsOk());

  struct NamedRegistry {
    std::string name;
    const SerializationRegistry* registry;
  };
  const Key& key = *GetParam().key;
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
