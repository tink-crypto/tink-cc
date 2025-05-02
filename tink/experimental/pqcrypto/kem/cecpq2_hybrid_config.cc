// Copyright 2021 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

#include "tink/experimental/pqcrypto/kem/cecpq2_hybrid_config.h"

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/aead/aead_config.h"
#include "tink/config/tink_fips.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_aead_hkdf_private_key_manager.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_aead_hkdf_public_key_manager.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_proto_serialization.h"
#include "tink/hybrid/hybrid_decrypt_wrapper.h"
#include "tink/hybrid/hybrid_encrypt_wrapper.h"
#include "tink/registry.h"

namespace crypto {
namespace tink {

absl::Status Cecpq2HybridConfigRegister() {
  auto status = AeadConfig::Register();
  if (!status.ok()) {
    return status;
  }

  // Register primitive wrappers
  status = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<HybridEncryptWrapper>());
  if (!status.ok()) {
    return status;
  }
  status = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<HybridDecryptWrapper>());
  if (!status.ok()) {
    return status;
  }

  // Currently there are no CECPQ2 hybrid encryption key managers which only use
  // FIPS-validated implementations, therefore none will be registered in
  // FIPS only mode
  if (IsFipsModeEnabled()) {
    return absl::OkStatus();
  }

  // Register CECPQ2 proto serialization.
  status = RegisterCecpq2ProtoSerialization();
  if (!status.ok()) {
    return status;
  }

  // Register non-FIPS hybrid-hybrid key managers
  status = Registry::RegisterAsymmetricKeyManagers(
      absl::make_unique<Cecpq2AeadHkdfPrivateKeyManager>(),
      absl::make_unique<Cecpq2AeadHkdfPublicKeyManager>(), true);
  if (!status.ok()) {
    return status;
  }

  return absl::OkStatus();
}

}  // namespace tink
}  // namespace crypto
