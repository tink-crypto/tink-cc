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

#include "tink/keyderivation/internal/key_gen_config_2026.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyderivation/internal/prf_based_deriver_key_manager.h"
#include "tink/keyderivation/internal/prf_based_key_derivation_test_vectors.h"
#include "tink/keyderivation/prf_based_key_derivation_key.h"
#include "tink/parameters.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;

TEST(KeyDerivationKeyGenV0Test, KeyManagers) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddKeyDerivationKeyGen2026(key_gen_config), IsOk());
  absl::StatusOr<const KeyTypeInfoStore*> key_gen_store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  EXPECT_THAT((*key_gen_store)->Get(PrfBasedDeriverKeyManager().get_key_type()),
              IsOk());
}

TEST(KeyDerivationKeyGenV0Test, SerializationRegistry) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddKeyDerivationKeyGen2026(key_gen_config), IsOk());
  absl::StatusOr<SerializationRegistry*> registry =
      KeyGenConfigurationImpl::GetSerializationRegistry(key_gen_config);
  ASSERT_THAT(registry, IsOk());

  const PrfBasedKeyDerivationKey& key =
      GetPrfBasedKeyDerivationHkdfTestVector().key;
  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params =
      (*registry)->SerializeParameters<ProtoParametersSerialization>(
          key.GetParameters());
  ASSERT_THAT(serialized_params, IsOk());
  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params =
      (*registry)->ParseParameters(**serialized_params);
  ASSERT_THAT(parsed_params, IsOk());
  EXPECT_EQ(**parsed_params, key.GetParameters());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      (*registry)->SerializeKey<ProtoKeySerialization>(
          key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      (*registry)->ParseKey(**serialized_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_EQ(**parsed_key, key);
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
