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
////////////////////////////////////////////////////////////////////////////////

#include "tink/aead/internal/kms_aead_config_2026.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/internal/kms_aead_key_gen_config_2026.h"
#include "tink/aead/kms_aead_key_manager.h"
#include "tink/aead/kms_envelope_aead_key_manager.h"
#include "tink/aead/legacy_kms_aead_key.h"
#include "tink/aead/legacy_kms_aead_parameters.h"
#include "tink/aead/legacy_kms_envelope_aead_key.h"
#include "tink/aead/legacy_kms_envelope_aead_parameters.h"
#include "tink/configuration.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/parameters.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::TestWithParam;
using ::testing::Values;

std::shared_ptr<const Key> CreateLegacyKmsAeadTestKey() {
  absl::StatusOr<LegacyKmsAeadParameters> kms_params =
      LegacyKmsAeadParameters::Create("some_key_uri",
                                      LegacyKmsAeadParameters::Variant::kTink);
  ABSL_CHECK_OK(kms_params);
  absl::StatusOr<LegacyKmsAeadKey> kms_key =
      LegacyKmsAeadKey::Create(*kms_params, /*id_requirement=*/123);
  ABSL_CHECK_OK(kms_key);
  return std::make_shared<LegacyKmsAeadKey>(*kms_key);
}

std::shared_ptr<const Key> CreateLegacyKmsEnvelopeAeadTestKey() {
  absl::StatusOr<AesGcmParameters> dek_params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(dek_params);
  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> envelope_params =
      LegacyKmsEnvelopeAeadParameters::Create(
          "some_key_uri", LegacyKmsEnvelopeAeadParameters::Variant::kTink,
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesGcm,
          *dek_params);
  ABSL_CHECK_OK(envelope_params);
  absl::StatusOr<LegacyKmsEnvelopeAeadKey> envelope_key =
      LegacyKmsEnvelopeAeadKey::Create(*envelope_params,
                                       /*id_requirement=*/456);
  ABSL_CHECK_OK(envelope_key);
  return std::make_shared<LegacyKmsEnvelopeAeadKey>(*envelope_key);
}

TEST(KmsAeadV0Test, KeyManagers) {
  Configuration config;
  ASSERT_THAT(AddKmsAead2026(config), IsOk());
  absl::StatusOr<const KeyTypeInfoStore*> store =
      ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddKmsAeadKeyGen2026(key_gen_config), IsOk());
  absl::StatusOr<const KeyTypeInfoStore*> key_gen_store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  for (const KeyTypeInfoStore* s : {*store, *key_gen_store}) {
    EXPECT_THAT(s->Get(KmsAeadKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(KmsEnvelopeAeadKeyManager().get_key_type()), IsOk());
  }
}

using KmsAeadSerializationTest = TestWithParam<std::shared_ptr<const Key>>;

INSTANTIATE_TEST_SUITE_P(KmsAeadSerializationTestSuite,
                         KmsAeadSerializationTest,
                         Values(CreateLegacyKmsAeadTestKey(),
                                CreateLegacyKmsEnvelopeAeadTestKey()));

TEST_P(KmsAeadSerializationTest, SerializationRegistry) {
  Configuration config;
  ASSERT_THAT(AddKmsAead2026(config), IsOk());
  absl::StatusOr<SerializationRegistry*> registry =
      ConfigurationImpl::GetSerializationRegistry(config);
  ASSERT_THAT(registry, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddKmsAeadKeyGen2026(key_gen_config), IsOk());
  absl::StatusOr<SerializationRegistry*> key_gen_registry =
      KeyGenConfigurationImpl::GetSerializationRegistry(key_gen_config);
  ASSERT_THAT(key_gen_registry, IsOk());

  const Key& key = *GetParam();
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
