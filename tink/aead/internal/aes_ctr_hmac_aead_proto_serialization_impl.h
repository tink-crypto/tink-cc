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

#ifndef TINK_AEAD_INTERNAL_AES_CTR_HMAC_AEAD_PROTO_SERIALIZATION_IMPL_H_
#define TINK_AEAD_INTERNAL_AES_CTR_HMAC_AEAD_PROTO_SERIALIZATION_IMPL_H_

#include "absl/status/status.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/serialization_registry.h"

namespace crypto {
namespace tink {
namespace internal {

// Registers proto parsers and serializers for AES-CTR-HMAC parameters and
// keys into specified mutable serialization `registry`.
absl::Status RegisterAesCtrHmacAeadProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry);

// Registers proto parsers and serializers for AES-CTR-HMAC parameters and
// keys into specified immutable serialization registry `builder`.
absl::Status RegisterAesCtrHmacAeadProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_AES_CTR_HMAC_AEAD_PROTO_SERIALIZATION_IMPL_H_
