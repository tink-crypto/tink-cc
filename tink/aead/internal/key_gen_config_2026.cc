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

#include "tink/aead/internal/key_gen_config_2026.h"

#include <memory>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/aes_ctr_hmac_aead_proto_serialization.h"
#include "tink/aead/aes_eax_key_manager.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/aes_eax_proto_serialization.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_proto_serialization.h"
#include "tink/aead/aes_gcm_siv_key_manager.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/aead/aes_gcm_siv_proto_serialization.h"
#include "tink/aead/internal/aes_ctr_hmac_key_creator.h"
#include "tink/aead/internal/aes_eax_key_creator.h"
#include "tink/aead/internal/aes_gcm_key_creator.h"
#include "tink/aead/internal/aes_gcm_siv_key_creator.h"
#include "tink/aead/internal/xchacha20_poly1305_key_creator.h"
#include "tink/aead/x_aes_gcm_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/aead/xchacha20_poly1305_proto_serialization.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/key_gen_configuration.h"

namespace crypto {
namespace tink {
namespace internal {

absl::Status AddAeadKeyGen2026(KeyGenConfiguration& config) {
  // TODO(b/296630956): Alphabetize in all AEAD config files.
  absl::Status status = internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      std::make_unique<AesCtrHmacAeadKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  if (absl::Status status = RegisterAesCtrHmacAeadProtoSerialization();
      !status.ok()) {
    return status;
  }
  if (absl::Status status = internal::KeyGenConfigurationImpl::AddKeyCreator<
          AesCtrHmacAeadParameters>(CreateAesCtrHmacKey, config);
      !status.ok()) {
    return status;
  }

  status = internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      std::make_unique<AesGcmKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }

  if (absl::Status status = RegisterAesGcmProtoSerialization(); !status.ok()) {
    return status;
  }
  if (absl::Status status =
          internal::KeyGenConfigurationImpl::AddKeyCreator<AesGcmParameters>(
              CreateAesGcmKey, config);
      !status.ok()) {
    return status;
  }

  status = internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      std::make_unique<AesGcmSivKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  ABSL_RETURN_IF_ERROR(RegisterAesGcmSivProtoSerialization());
  ABSL_RETURN_IF_ERROR(
      internal::KeyGenConfigurationImpl::AddKeyCreator<AesGcmSivParameters>(
          CreateAesGcmSivKey, config));

  status = internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      std::make_unique<AesEaxKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }

  ABSL_RETURN_IF_ERROR(RegisterAesEaxProtoSerialization());
  ABSL_RETURN_IF_ERROR(
      internal::KeyGenConfigurationImpl::AddKeyCreator<AesEaxParameters>(
          CreateAesEaxKey, config));

  status = internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      CreateXAesGcmKeyManager(), config);
  if (!status.ok()) {
    return status;
  }
  ABSL_RETURN_IF_ERROR(RegisterXChaCha20Poly1305ProtoSerialization());
  ABSL_RETURN_IF_ERROR(
      internal::KeyGenConfigurationImpl::AddKeyCreator<
          XChaCha20Poly1305Parameters>(CreateXChaCha20Poly1305Key, config));
  return internal::KeyGenConfigurationImpl::AddKeyTypeManager(
      std::make_unique<XChaCha20Poly1305KeyManager>(), config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
