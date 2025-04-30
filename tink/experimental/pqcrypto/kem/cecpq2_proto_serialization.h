// Copyright 2025 Google LLC
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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_KEM_CECPQ2_PROTO_SERIALIZATION_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_KEM_CECPQ2_PROTO_SERIALIZATION_H_

#include "absl/status/status.h"
#include "tink/experimental/pqcrypto/kem/internal/cecpq2_proto_serialization_impl.h"
#include "tink/internal/mutable_serialization_registry.h"

namespace crypto {
namespace tink {

// Registers proto parsers and serializers for CECPQ2 parameters and keys into
// global serialization `registry`.
inline absl::Status RegisterCecpq2ProtoSerialization() {
  return internal::RegisterCecpq2ProtoSerializationWithMutableRegistry(
      internal::MutableSerializationRegistry::GlobalInstance());
}

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_KEM_CECPQ2_PROTO_SERIALIZATION_H_
