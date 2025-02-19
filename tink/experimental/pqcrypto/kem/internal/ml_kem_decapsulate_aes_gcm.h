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
///////////////////////////////////////////////////////////////////////////////

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_KEM_INTERNAL_ML_KEM_DECAPSULATE_AES_GCM_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_KEM_INTERNAL_ML_KEM_DECAPSULATE_AES_GCM_H_

#include <memory>

#include "tink/aead/aes_gcm_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"
#include "tink/kem/kem_decapsulate.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Creates a new KemDecapsulate instance that uses the BoringSSL implementation
// of ML-KEM, and derives an AES-256-GCM instance directly from the shared
// secret (i.e. the 32-byte shared secret is used as the AES-GCM key).
//
// This function will return an error if the AesGcmParameters have an ID
// requirement.
absl::StatusOr<std::unique_ptr<KemDecapsulate>> NewMlKemDecapsulateAes256Gcm(
    MlKemPrivateKey recipient_key, AesGcmParameters aes_gcm_parameters);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_KEM_INTERNAL_ML_KEM_DECAPSULATE_AES_GCM_H_
