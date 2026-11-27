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

#include "tink/daead/internal/key_gen_config_2026.h"

#include "absl/memory/memory.h"
#include "absl/status/status_macros.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/daead/internal/aes_siv_key_creator.h"
#include "tink/daead/internal/aes_siv_proto_serialization_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/serialization_registry.h"
#include "tink/key_gen_configuration.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

absl::Status AddDeterministicAeadKeyGen2026(KeyGenConfiguration& config) {
  ABSL_ASSIGN_OR_RETURN(
      SerializationRegistry * serialization_registry,
      KeyGenConfigurationImpl::GetSerializationRegistry(config));
  ABSL_RETURN_IF_ERROR(
      RegisterAesSivProtoSerializationWithRegistry(*serialization_registry));
  ABSL_RETURN_IF_ERROR(
      KeyGenConfigurationImpl::AddKeyCreator<AesSivParameters>(
          CreateAesSivKey, config));
  return KeyGenConfigurationImpl::AddKeyTypeManager(
      std::make_unique<AesSivKeyManager>(), config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
