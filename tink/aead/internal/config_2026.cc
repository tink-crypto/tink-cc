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

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "tink/aead/aead_wrapper.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_eax_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_siv_key_manager.h"
#include "tink/aead/cord_aead_wrapper.h"
#include "tink/aead/internal/aes_ctr_hmac_aead_proto_serialization_impl.h"
#include "tink/aead/internal/aes_eax_proto_serialization_impl.h"
#include "tink/aead/internal/aes_gcm_proto_serialization_impl.h"
#include "tink/aead/internal/aes_gcm_siv_proto_serialization_impl.h"
#include "tink/aead/internal/x_aes_gcm_proto_serialization_impl.h"
#include "tink/aead/internal/xchacha20_poly1305_proto_serialization_impl.h"
#include "tink/aead/x_aes_gcm_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/serialization_registry.h"

namespace crypto {
namespace tink {
namespace internal {

absl::Status AddAead2026(Configuration& config) {
  ABSL_ASSIGN_OR_RETURN(SerializationRegistry * serialization_registry,
                        ConfigurationImpl::GetSerializationRegistry(config));
  ABSL_RETURN_IF_ERROR(RegisterAesCtrHmacAeadProtoSerializationWithRegistry(
      *serialization_registry));
  ABSL_RETURN_IF_ERROR(
      RegisterAesEaxProtoSerializationWithRegistry(*serialization_registry));
  ABSL_RETURN_IF_ERROR(
      RegisterAesGcmProtoSerializationWithRegistry(*serialization_registry));
  ABSL_RETURN_IF_ERROR(
      RegisterAesGcmSivProtoSerializationWithRegistry(*serialization_registry));
  ABSL_RETURN_IF_ERROR(
      RegisterXAesGcmProtoSerializationWithRegistry(*serialization_registry));
  ABSL_RETURN_IF_ERROR(RegisterXChaCha20Poly1305ProtoSerializationWithRegistry(
      *serialization_registry));

  absl::Status status = ConfigurationImpl::AddPrimitiveWrapper(
      std::make_unique<AeadWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      std::make_unique<CordAeadWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddKeyTypeManager(
      std::make_unique<AesCtrHmacAeadKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddKeyTypeManager(
      std::make_unique<AesEaxKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddKeyTypeManager(
      std::make_unique<AesGcmKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddKeyTypeManager(
      std::make_unique<AesGcmSivKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status =
      ConfigurationImpl::AddKeyTypeManager(CreateXAesGcmKeyManager(), config);
  if (!status.ok()) {
    return status;
  }
  return ConfigurationImpl::AddKeyTypeManager(
      std::make_unique<XChaCha20Poly1305KeyManager>(), config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
