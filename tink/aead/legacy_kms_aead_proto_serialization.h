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

#ifndef TINK_AEAD_LEGACY_KMS_AEAD_PROTO_SERIALIZATION_H_
#define TINK_AEAD_LEGACY_KMS_AEAD_PROTO_SERIALIZATION_H_

#include "tink/aead/internal/legacy_kms_aead_proto_serialization_impl.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

// Registers proto parsers and serializers for legacy KMS AEAD parameters and
// keys into global serialization registry.
inline absl::Status RegisterLegacyKmsAeadProtoSerialization() {
  return internal::RegisterLegacyKmsAeadProtoSerializationWithMutableRegistry(
      internal::MutableSerializationRegistry::GlobalInstance());
}

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_LEGACY_KMS_AEAD_PROTO_SERIALIZATION_H_
