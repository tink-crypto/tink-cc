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

#include "tink/mac/internal/config_2026.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/chunked_mac.h"
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
#include "tink/mac.h"
#include "tink/mac/aes_cmac_key_manager.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/mac/internal/aes_cmac_test_vectors.h"
#include "tink/mac/internal/hmac_test_vectors.h"
#include "tink/mac/internal/key_gen_config_2026.h"
#include "tink/mac/mac_key_templates.h"
#include "tink/parameters.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::google::crypto::tink::KeyTemplate;
using ::testing::TestWithParam;
using ::testing::Values;

TEST(Mac2026Test, PrimitiveWrappers) {
  Configuration config;
  ASSERT_THAT(AddMac2026(config), IsOk());
  absl::StatusOr<const KeysetWrapperStore*> store =
      ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<Mac>(), IsOk());
  EXPECT_THAT((*store)->Get<ChunkedMac>(), IsOk());
}

TEST(Mac2026Test, KeyManagers) {
  Configuration config;
  ASSERT_THAT(AddMac2026(config), IsOk());
  absl::StatusOr<const KeyTypeInfoStore*> store =
      ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddMacKeyGen2026(key_gen_config), IsOk());
  absl::StatusOr<const KeyTypeInfoStore*> key_gen_store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  for (const KeyTypeInfoStore* s : {*store, *key_gen_store}) {
    EXPECT_THAT(s->Get(AesCmacKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(HmacKeyManager().get_key_type()), IsOk());
  }
}

using Mac2026KeyTypesTest = TestWithParam<KeyTemplate>;

INSTANTIATE_TEST_SUITE_P(Mac2026KeyTypesTestSuite, Mac2026KeyTypesTest,
                         Values(MacKeyTemplates::AesCmac(),
                                MacKeyTemplates::HmacSha256()));

TEST_P(Mac2026KeyTypesTest, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddMacKeyGen2026(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddMac2026(config), IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), key_gen_config);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<Mac>> mac =
      (*handle)->GetPrimitive<Mac>(config);
  ASSERT_THAT(mac, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> tag = (*mac)->ComputeMac(data);
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT((*mac)->VerifyMac(*tag, data), IsOk());
}

TEST_P(Mac2026KeyTypesTest, GetPrimitiveChunkedMac) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddMacKeyGen2026(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddMac2026(config), IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), key_gen_config);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      (*handle)->GetPrimitive<ChunkedMac>(config);
  ASSERT_THAT(chunked_mac, IsOk());

  std::string data1 = "da";
  std::string data2 = "ta";

  absl::StatusOr<std::unique_ptr<ChunkedMacComputation>> compute =
      (*chunked_mac)->CreateComputation();
  ASSERT_THAT(compute, IsOk());
  ASSERT_THAT((*compute)->Update(data1), IsOk());
  ASSERT_THAT((*compute)->Update(data2), IsOk());
  absl::StatusOr<std::string> tag = (*compute)->ComputeMac();
  ASSERT_THAT(tag, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> verify =
      (*chunked_mac)->CreateVerification(*tag);
  ASSERT_THAT(verify, IsOk());
  ASSERT_THAT((*verify)->Update(data1), IsOk());
  ASSERT_THAT((*verify)->Update(data2), IsOk());
  EXPECT_THAT((*verify)->VerifyMac(), IsOk());
}

TEST(Mac2026Test, GenerateNewFromAesCmacParameters) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddMacKeyGen2026(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddMac2026(config), IsOk());

  absl::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*params, key_gen_config);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<Mac>> mac =
      (*handle)->GetPrimitive<Mac>(config);
  ASSERT_THAT(mac, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> tag = (*mac)->ComputeMac(data);
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT((*mac)->VerifyMac(*tag, data), IsOk());
}

TEST(Mac2026Test, GenerateNewFromHmacParameters) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddMacKeyGen2026(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddMac2026(config), IsOk());

  absl::StatusOr<HmacParameters> params = HmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      HmacParameters::HashType::kSha256, HmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*params, key_gen_config);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<Mac>> mac =
      (*handle)->GetPrimitive<Mac>(config);
  ASSERT_THAT(mac, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> tag = (*mac)->ComputeMac(data);
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT((*mac)->VerifyMac(*tag, data), IsOk());
}

struct NamedKey {
  std::string test_name;
  const Key* key;
};

using Mac2026SerializationTest = TestWithParam<NamedKey>;

INSTANTIATE_TEST_SUITE_P(
    Mac2026SerializationTestSuite, Mac2026SerializationTest,
    Values(NamedKey{"AesCmac",
                    &GetAesCmacTestVector(/*key_size_in_bytes=*/32).key},
           NamedKey{"Hmac",
                    &GetHmacTestVector(/*key_size_in_bytes=*/40,
                                       HmacParameters::HashType::kSha256,
                                       HmacParameters::Variant::kTink)
                         .key}),
    [](const testing::TestParamInfo<NamedKey>& info) {
      return info.param.test_name;
    });

TEST_P(Mac2026SerializationTest, SerializationRegistry) {
  Configuration config;
  ASSERT_THAT(AddMac2026(config), IsOk());
  absl::StatusOr<SerializationRegistry*> registry =
      ConfigurationImpl::GetSerializationRegistry(config);
  ASSERT_THAT(registry, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddMacKeyGen2026(key_gen_config), IsOk());
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
