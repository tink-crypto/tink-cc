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

#ifndef TINK_AEAD_INTERNAL_ZERO_COPY_AES_CTR_HMAC_BORINGSSL_H_
#define TINK_AEAD_INTERNAL_ZERO_COPY_AES_CTR_HMAC_BORINGSSL_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "tink/aead/aes_ctr_hmac_aead_key.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"

namespace crypto {
namespace tink {
namespace internal {

class ZeroCopyAesCtrHmacBoringSsl : public ZeroCopyAead {
 public:
  static absl::StatusOr<std::unique_ptr<ZeroCopyAead>> New(
      const AesCtrHmacAeadKey& key);

  int64_t MaxEncryptionSize(int64_t plaintext_size) const override;

  absl::StatusOr<int64_t> Encrypt(absl::string_view plaintext,
                                  absl::string_view associated_data,
                                  absl::Span<char> buffer) const override;

  int64_t MaxDecryptionSize(int64_t ciphertext_size) const override;

  absl::StatusOr<int64_t> Decrypt(absl::string_view ciphertext,
                                  absl::string_view associated_data,
                                  absl::Span<char> buffer) const override;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

 private:
  ZeroCopyAesCtrHmacBoringSsl(
      internal::SslUniquePtr<EVP_CIPHER_CTX> base_aes_ctx,
      internal::SslUniquePtr<HMAC_CTX> base_hmac_ctx, int iv_size, int tag_size,
      absl::string_view output_prefix)
      : base_aes_ctx_(std::move(base_aes_ctx)),
        base_hmac_ctx_(std::move(base_hmac_ctx)),
        iv_size_(iv_size),
        tag_size_(tag_size),
        output_prefix_(output_prefix) {}

  const internal::SslUniquePtr<EVP_CIPHER_CTX> base_aes_ctx_;
  const internal::SslUniquePtr<HMAC_CTX> base_hmac_ctx_;
  const int iv_size_;
  const int tag_size_;
  const std::string output_prefix_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_ZERO_COPY_AES_CTR_HMAC_BORINGSSL_H_
