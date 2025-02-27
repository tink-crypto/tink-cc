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

#include "tink/hybrid/internal/config_v0.h"
#include <memory>

#include "absl/memory/memory.h"
#include "tink/configuration.h"
#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"
#include "tink/hybrid/hybrid_decrypt_wrapper.h"
#include "tink/hybrid/hybrid_encrypt_wrapper.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/util/statusor.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_proto_serialization.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid/internal/hpke_decrypt.h"
#include "tink/hybrid/internal/hpke_encrypt.h"
#include "tink/hybrid/internal/hpke_private_key_manager.h"
#include "tink/hybrid/internal/hpke_public_key_manager.h"
#endif
#include "tink/internal/configuration_impl.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

#ifdef OPENSSL_IS_BORINGSSL
absl::StatusOr<std::unique_ptr<HybridDecrypt>> NewHpkeDecrypt(
    const HpkePrivateKey& key) {
  return crypto::tink::internal::HpkeDecrypt::New(key);
}

absl::StatusOr<std::unique_ptr<HybridEncrypt>> NewHpkeEncrypt(
    const HpkePublicKey& key) {
  return crypto::tink::internal::HpkeEncrypt::New(key);
}
#endif

}  // namespace

absl::Status AddHybridV0(Configuration& config) {
  absl::Status status = ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<HybridEncryptWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<HybridDecryptWrapper>(), config);
  if (!status.ok()) {
    return status;
  }

#ifdef OPENSSL_IS_BORINGSSL
  status = ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<HpkePrivateKeyManager>(),
      absl::make_unique<HpkePublicKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = RegisterHpkeProtoSerialization();
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddPrimitiveGetter<HybridDecrypt, HpkePrivateKey>(
      NewHpkeDecrypt, config);
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddPrimitiveGetter<HybridEncrypt, HpkePublicKey>(
      NewHpkeEncrypt, config);
  if (!status.ok()) {
    return status;
  }
#endif
  return ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<EciesAeadHkdfPrivateKeyManager>(),
      absl::make_unique<EciesAeadHkdfPublicKeyManager>(), config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
