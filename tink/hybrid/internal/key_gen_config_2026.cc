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

#include "tink/hybrid/internal/key_gen_config_2026.h"

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "tink/hybrid/internal/hpke_private_key_manager.h"
#include "tink/hybrid/internal/hpke_public_key_manager.h"
#endif
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/key_gen_configuration.h"

namespace crypto {
namespace tink {
namespace internal {

absl::Status AddHybridKeyGen2026(KeyGenConfiguration& config) {
#ifdef OPENSSL_IS_BORINGSSL
  absl::Status status = KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
      std::make_unique<HpkePrivateKeyManager>(),
      std::make_unique<HpkePublicKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
#endif
  return KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
      std::make_unique<EciesAeadHkdfPrivateKeyManager>(),
      std::make_unique<EciesAeadHkdfPublicKeyManager>(), config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
