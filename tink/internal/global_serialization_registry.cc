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
#include "tink/aead/internal/aes_ctr_hmac_aead_proto_serialization_impl.h"
#include "tink/aead/internal/aes_eax_proto_serialization_impl.h"
#include "tink/aead/internal/aes_gcm_proto_serialization_impl.h"
#include "tink/aead/internal/aes_gcm_siv_proto_serialization_impl.h"
#include "tink/aead/internal/chacha20_poly1305_proto_serialization_impl.h"
#include "tink/aead/internal/legacy_kms_aead_proto_serialization_impl.h"
#include "tink/aead/internal/x_aes_gcm_proto_serialization_impl.h"
#include "tink/aead/internal/xchacha20_poly1305_proto_serialization_impl.h"
#include "tink/daead/internal/aes_siv_proto_serialization_impl.h"
#include "tink/internal/serialization_registry.h"
#include "tink/mac/internal/aes_cmac_proto_serialization_impl.h"
#include "tink/mac/internal/hmac_proto_serialization_impl.h"
#include "tink/prf/internal/aes_cmac_prf_proto_serialization_impl.h"
#include "tink/prf/internal/hkdf_prf_proto_serialization_impl.h"
#include "tink/prf/internal/hmac_prf_proto_serialization_impl.h"
#include "tink/signature/internal/ecdsa_proto_serialization_impl.h"
#include "tink/signature/internal/ed25519_proto_serialization_impl.h"
#include "tink/streamingaead/internal/aes_gcm_hkdf_streaming_proto_serialization_impl.h"

namespace crypto {
namespace tink {
namespace internal {

const SerializationRegistry& GlobalSerializationRegistry() {
  static const SerializationRegistry* instance = [] {
    SerializationRegistry::Builder builder;

    // AEAD
    CHECK_OK(
        RegisterAesCtrHmacAeadProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(RegisterAesEaxProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(RegisterAesGcmProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(RegisterAesGcmSivProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(
        RegisterChaCha20Poly1305ProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(
        RegisterLegacyKmsAeadProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(RegisterXAesGcmProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(RegisterXChaCha20Poly1305ProtoSerializationWithRegistryBuilder(
        builder));

    // Deterministic AEAD
    CHECK_OK(RegisterAesSivProtoSerializationWithRegistryBuilder(builder));

    // Hybrid

    // JWT

    // Key derivation

    // MAC
    CHECK_OK(RegisterAesCmacProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(RegisterHmacProtoSerializationWithRegistryBuilder(builder));

    // PRF
    CHECK_OK(RegisterAesCmacPrfProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(RegisterHkdfPrfProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(RegisterHmacPrfProtoSerializationWithRegistryBuilder(builder));

    // Signature
    CHECK_OK(RegisterEcdsaProtoSerializationWithRegistryBuilder(builder));
    CHECK_OK(RegisterEd25519ProtoSerializationWithRegistryBuilder(builder));

    // Streaming AEAD
    CHECK_OK(RegisterAesGcmHkdfStreamingProtoSerializationWithRegistryBuilder(
        builder));

    static SerializationRegistry* registry =
        new SerializationRegistry(std::move(builder).Build());
    return registry;
  }();
  return *instance;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
