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

#ifndef TINK_AEAD_INTERNAL_BASE_X_AES_GCM_H_
#define TINK_AEAD_INTERNAL_BASE_X_AES_GCM_H_

#include <memory>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "openssl/cmac.h"
#include "openssl/evp.h"
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

// Internal class to perform per message key derivation in X-AES-GCM
// Performs KDF in CTR mode, as specified in: SP-800 - 108r1, using AES-CMAC as
// the underlying PRF.
class BaseXAesGcm {
 public:
  static absl::StatusOr<BaseXAesGcm> New(crypto::tink::XAesGcmKey key);

  // move-only
  BaseXAesGcm(BaseXAesGcm&& other) = default;
  BaseXAesGcm& operator=(BaseXAesGcm&& other) = default;
  BaseXAesGcm(const BaseXAesGcm&) = delete;
  BaseXAesGcm& operator=(const BaseXAesGcm&) = delete;

  static constexpr int kMaxSaltSize = 12;

  absl::StatusOr<crypto::tink::util::SecretData> DerivePerMessageKey(
      absl::string_view salt) const;

  int salt_size() const { return salt_size_; }

  int min_ct_size() const;

 private:
  explicit BaseXAesGcm(crypto::tink::internal::SslUniquePtr<CMAC_CTX> cmac_ctx,
                       int salt_size)
      : cmac_ctx_(std::move(cmac_ctx)), salt_size_(salt_size) {}
  crypto::tink::internal::SslUniquePtr<CMAC_CTX> cmac_ctx_;
  const int salt_size_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_BASE_X_AES_GCM_H_
