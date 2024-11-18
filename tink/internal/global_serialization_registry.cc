// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/internal/global_serialization_registry.h"

#include <utility>

#include "absl/log/check.h"
#include "tink/aead/internal/chacha20_poly1305_proto_serialization_impl.h"
#include "tink/aead/internal/legacy_kms_aead_proto_serialization_impl.h"
#include "tink/aead/internal/x_aes_gcm_proto_serialization_impl.h"
#include "tink/aead/internal/xchacha20_poly1305_proto_serialization_impl.h"
#include "tink/internal/serialization_registry.h"
#include "tink/prf/internal/aes_cmac_prf_proto_serialization_impl.h"
#include "tink/prf/internal/hkdf_prf_proto_serialization_impl.h"
#include "tink/prf/internal/hmac_prf_proto_serialization_impl.h"

namespace crypto {
namespace tink {
namespace internal {

const SerializationRegistry& GlobalSerializationRegistry() {
  static const SerializationRegistry* instance = [] {
    SerializationRegistry::Builder builder;

    // AEAD
    CHECK_OK(
        RegisterChaCha20Poly1305ProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(
        RegisterLegacyKmsAeadProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(RegisterXAesGcmProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(RegisterXChaCha20Poly1305ProtoSerializationWithRegistryBuilder(
        builder));

    // Deterministic AEAD

    // Hybrid

    // JWT

    // Key derivation

    // MAC

    // PRF
    CHECK_OK(RegisterAesCmacPrfProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(RegisterHkdfPrfProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(RegisterHmacPrfProtoSerializationWithRegistryBuilder(builder));

    // Signature

    // Streaming AEAD

    static SerializationRegistry* registry =
        new SerializationRegistry(std::move(builder).Build());
    return registry;
  }();
  return *instance;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
