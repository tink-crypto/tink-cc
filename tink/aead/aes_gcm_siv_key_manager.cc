// Copyright 2026 Google LLC
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

#include "tink/aead/aes_gcm_siv_key_manager.h"

#include <memory>
#include <optional>

#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/aead/aes_gcm_siv_key.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/internal/cord_aes_gcm_siv_boringssl.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/aes_gcm_siv_boringssl.h"
#include "tink/util/secret_data.h"
#include "proto/aes_gcm_siv.pb.h"

namespace crypto {
namespace tink {

absl::StatusOr<std::unique_ptr<Aead>> AesGcmSivKeyManager::AeadFactory::Create(
    const google::crypto::tink::AesGcmSivKey& key) const {
  return subtle::AesGcmSivBoringSsl::New(
      util::SecretDataFromStringView(key.key_value()));
}

absl::StatusOr<std::unique_ptr<CordAead>>
AesGcmSivKeyManager::CordAeadFactory::Create(
    const google::crypto::tink::AesGcmSivKey& key) const {
  absl::StatusOr<AesGcmSivParameters> params = AesGcmSivParameters::Create(
      key.key_value().size(), AesGcmSivParameters::Variant::kNoPrefix);
  if (!params.ok()) {
    return params.status();
  }
  absl::StatusOr<crypto::tink::AesGcmSivKey> siv_key =
      crypto::tink::AesGcmSivKey::Create(
          *params,
          RestrictedData(key.key_value(), InsecureSecretKeyAccess::Get()),
          /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  if (!siv_key.ok()) {
    return siv_key.status();
  }
  return internal::NewCordAesGcmSivBoringSsl(*siv_key);
}

}  // namespace tink
}  // namespace crypto
