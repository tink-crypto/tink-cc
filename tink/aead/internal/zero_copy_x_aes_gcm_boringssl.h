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

#ifndef TINK_AEAD_INTERNAL_ZERO_COPY_X_AES_GCM_BORINGSSL_H_
#define TINK_AEAD_INTERNAL_ZERO_COPY_X_AES_GCM_BORINGSSL_H_

#include <memory>

#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<crypto::tink::internal::ZeroCopyAead>>
NewZeroCopyXAesGcmBoringSsl(const crypto::tink::XAesGcmKey& key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_ZERO_COPY_X_AES_GCM_BORINGSSL_H_
