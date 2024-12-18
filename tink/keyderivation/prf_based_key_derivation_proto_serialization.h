// Copyright 2024 Google LLC
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

#ifndef TINK_KEYDERIVATION_PRF_BASED_KEY_DERIVATION_PROTO_SERIALIZATION_H_
#define TINK_KEYDERIVATION_PRF_BASED_KEY_DERIVATION_PROTO_SERIALIZATION_H_

#include "tink/internal/mutable_serialization_registry.h"
#include "tink/keyderivation/internal/prf_based_key_derivation_proto_serialization_impl.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

// Registers proto parsers and serializers for PRF-based key derivation
// parameters and keys into global serialization registry.
inline crypto::tink::util::Status
RegisterPrfBasedKeyDerivationProtoSerialization() {
  return internal::
      RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
          internal::MutableSerializationRegistry::GlobalInstance());
}

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYDERIVATION_PRF_BASED_KEY_DERIVATION_PROTO_SERIALIZATION_H_
