// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, embodiment or
// conditions of any kind, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/aead/internal/aes_gcm_key_creator.h"

#include <memory>
#include <optional>
#include <utility>

#include "absl/status/statusor.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/subtle/random.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<Key>> CreateAesGcmKey(
    const AesGcmParameters& parameters, std::optional<int> id_requirement) {
  absl::StatusOr<SecretData> key_bytes =
      subtle::Random::GetRandomKeyBytes(parameters.KeySizeInBytes());
  if (!key_bytes.ok()) {
    return key_bytes.status();
  }
  RestrictedData restricted_key_bytes(*std::move(key_bytes),
                                      InsecureSecretKeyAccess::Get());
  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      parameters, restricted_key_bytes, id_requirement, GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return std::make_unique<AesGcmKey>(*std::move(key));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
