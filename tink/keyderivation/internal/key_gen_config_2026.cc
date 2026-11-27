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

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/serialization_registry.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyderivation/internal/prf_based_deriver_key_manager.h"
#include "tink/keyderivation/internal/prf_based_key_derivation_key_creator.h"
#include "tink/keyderivation/internal/prf_based_key_derivation_proto_serialization_impl.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"

namespace crypto {
namespace tink {
namespace internal {

absl::Status AddKeyDerivationKeyGen2026(KeyGenConfiguration& config) {
  ABSL_ASSIGN_OR_RETURN(
      SerializationRegistry* serialization_registry,
      KeyGenConfigurationImpl::GetSerializationRegistry(config));
  ABSL_RETURN_IF_ERROR(
      RegisterPrfBasedKeyDerivationProtoSerializationWithRegistry(
          *serialization_registry));
  ABSL_RETURN_IF_ERROR(
      KeyGenConfigurationImpl::AddKeyCreator<PrfBasedKeyDerivationParameters>(
          CreatePrfBasedKeyDerivationKey, config));
  return KeyGenConfigurationImpl::AddKeyTypeManager(
      std::make_unique<PrfBasedDeriverKeyManager>(), config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
