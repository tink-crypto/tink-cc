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

#ifndef TINK_AEAD_INTERNAL_CORD_AES_GCM_SIV_BORINGSSL_H_
#define TINK_AEAD_INTERNAL_CORD_AES_GCM_SIV_BORINGSSL_H_

#include <memory>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/aead/aes_gcm_siv_key.h"
#include "tink/aead/cord_aead.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

// Creates a new CordAead primitive for AES-GCM-SIV using BoringSSL.
absl::StatusOr<std::unique_ptr<CordAead>> NewCordAesGcmSivBoringSsl(
    const SecretData& key, absl::string_view output_prefix = "");

// Creates a new CordAead primitive for AES-GCM-SIV using BoringSSL from an
// AesGcmSivKey.
absl::StatusOr<std::unique_ptr<CordAead>> NewCordAesGcmSivBoringSsl(
    const AesGcmSivKey& key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_CORD_AES_GCM_SIV_BORINGSSL_H_
