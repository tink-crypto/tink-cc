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

#ifndef TINK_AEAD_INTERNAL_ZERO_COPY_XCHACHA20_POLY1305_BORINGSSL_H_
#define TINK_AEAD_INTERNAL_ZERO_COPY_XCHACHA20_POLY1305_BORINGSSL_H_

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead/internal/ssl_aead.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/internal/fips_utils.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

class ZeroCopyXChacha20Poly1305BoringSsl : public ZeroCopyAead {
 public:
  // Constructs a new ZeroCopyAead cipher for XChacha20-Poly1305.
  // Currently supported key size is 256 bits.
  // Currently supported nonce size is 24 bytes.
  // The tag size is fixed to 16 bytes.
  static absl::StatusOr<std::unique_ptr<ZeroCopyAead>> New(SecretData key);

  int64_t MaxEncryptionSize(int64_t plaintext_size) const override;

  absl::StatusOr<int64_t> Encrypt(absl::string_view plaintext,
                                  absl::string_view associated_data,
                                  absl::Span<char> buffer) const override;

  int64_t MaxDecryptionSize(int64_t ciphertext_size) const override;

  absl::StatusOr<int64_t> Decrypt(absl::string_view ciphertext,
                                  absl::string_view associated_data,
                                  absl::Span<char> buffer) const override;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

 private:
  explicit ZeroCopyXChacha20Poly1305BoringSsl(
      std::unique_ptr<SslOneShotAead> aead)
      : aead_(std::move(aead)) {}

  const std::unique_ptr<SslOneShotAead> aead_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_ZERO_COPY_XCHACHA20_POLY1305_BORINGSSL_H_
