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

#include "tink/aead/aes_gcm_key_manager.h"

#include <memory>
#include <utility>

#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/internal/cord_aes_gcm_boringssl.h"
#include "tink/subtle/aes_gcm_boringssl.h"
#include "tink/util/secret_data.h"
#include "proto/aes_gcm.pb.h"

namespace crypto {
namespace tink {

absl::StatusOr<std::unique_ptr<Aead>> AesGcmKeyManager::AeadFactory::Create(
    const google::crypto::tink::AesGcmKey& key) const {
  auto aes_gcm_result = subtle::AesGcmBoringSsl::New(
      util::SecretDataFromStringView(key.key_value()));
  if (!aes_gcm_result.ok()) return aes_gcm_result.status();
  return {std::move(aes_gcm_result.value())};
}

absl::StatusOr<std::unique_ptr<CordAead>>
AesGcmKeyManager::CordAeadFactory::Create(
    const google::crypto::tink::AesGcmKey& key) const {
  auto cord_aes_gcm_result = crypto::tink::internal::CordAesGcmBoringSsl::New(
      util::SecretDataFromStringView(key.key_value()));
  if (!cord_aes_gcm_result.ok()) return cord_aes_gcm_result.status();
  return {std::move(cord_aes_gcm_result.value())};
}

}  // namespace tink
}  // namespace crypto
