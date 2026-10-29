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

#include "tink/aead/internal/zero_copy_chacha20_poly1305_boringssl.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead/chacha20_poly1305_key.h"
#include "tink/aead/internal/ssl_aead.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/subtle/random.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

constexpr int kNonceSizeInBytes = 12;
constexpr int kTagSizeInBytes = 16;
constexpr int kOverheadInBytes = kNonceSizeInBytes + kTagSizeInBytes;

class ZeroCopyChaCha20Poly1305BoringSsl : public ZeroCopyAead {
 public:
  explicit ZeroCopyChaCha20Poly1305BoringSsl(
      std::unique_ptr<SslOneShotAead> aead,
      absl::string_view output_prefix = "")
      : aead_(std::move(aead)), output_prefix_(output_prefix) {}

  int64_t MaxEncryptionSize(int64_t plaintext_size) const override {
    // No need to call `aead_->CiphertextSize()` here as the overhead is known.
    return output_prefix_.size() + plaintext_size + kOverheadInBytes;
  }

  absl::StatusOr<int64_t> Encrypt(absl::string_view plaintext,
                                  absl::string_view associated_data,
                                  absl::Span<char> buffer) const override {
    const int64_t max_encryption_size = MaxEncryptionSize(plaintext.size());
    ABSL_CHECK_GE(max_encryption_size, 0);
    if (buffer.size() < static_cast<size_t>(max_encryption_size)) {
      return absl::InvalidArgumentError(
          absl::StrCat("Encryption buffer too small; expected at least ",
                       max_encryption_size, " bytes, got ", buffer.size()));
    }

    absl::string_view buffer_string(buffer.data(), buffer.size());
    if (BuffersOverlap(plaintext, buffer_string)) {
      return absl::FailedPreconditionError(
          "Plaintext and ciphertext buffers overlap; this is disallowed");
    }

    if (!output_prefix_.empty()) {
      std::copy(output_prefix_.begin(), output_prefix_.end(), buffer.begin());
    }

    absl::Span<char> buffer_after_prefix =
        buffer.subspan(output_prefix_.size());
    absl::Span<char> nonce_buffer =
        buffer_after_prefix.subspan(0, kNonceSizeInBytes);
    absl::Span<char> encrypted_buffer =
        buffer_after_prefix.subspan(kNonceSizeInBytes);

    ABSL_RETURN_IF_ERROR(subtle::Random::GetRandomBytes(nonce_buffer));
    ABSL_ASSIGN_OR_RETURN(
        int64_t written_bytes,
        aead_->Encrypt(plaintext, associated_data,
                       absl::string_view(nonce_buffer.data(),
                                         nonce_buffer.size()),
                       encrypted_buffer));
    return output_prefix_.size() + kNonceSizeInBytes + written_bytes;
  }

  int64_t MaxDecryptionSize(int64_t ciphertext_size) const override {
    // No need to call `aead_->PlaintextSize()` here as the overhead is known.
    const int64_t size =
        ciphertext_size - output_prefix_.size() - kOverheadInBytes;
    if (size <= 0) {
      return 0;
    }
    return size;
  }

  absl::StatusOr<int64_t> Decrypt(absl::string_view ciphertext,
                                  absl::string_view associated_data,
                                  absl::Span<char> buffer) const override {
    const size_t min_ciphertext_size = output_prefix_.size() + kOverheadInBytes;
    if (ciphertext.size() < min_ciphertext_size) {
      return absl::InvalidArgumentError(
          absl::StrCat("Ciphertext too short; expected at least ",
                       min_ciphertext_size, " got ", ciphertext.size()));
    }

    const int64_t max_decryption_size = MaxDecryptionSize(ciphertext.size());
    ABSL_CHECK_GE(max_decryption_size, 0);
    if (buffer.size() < static_cast<size_t>(max_decryption_size)) {
      return absl::InvalidArgumentError(
          absl::StrCat("Decryption buffer too small; expected at least ",
                       max_decryption_size, " bytes, got ", buffer.size()));
    }

    absl::string_view buffer_string(buffer.data(), buffer.size());
    if (BuffersOverlap(ciphertext, buffer_string)) {
      return absl::FailedPreconditionError(
          "Plaintext and ciphertext buffers overlap; this is disallowed");
    }

    if (!output_prefix_.empty()) {
      if (!absl::StartsWith(ciphertext, output_prefix_)) {
        return absl::InvalidArgumentError("Prefix mismatch");
      }
      ciphertext.remove_prefix(output_prefix_.size());
    }

    absl::string_view nonce = ciphertext.substr(0, kNonceSizeInBytes);
    absl::string_view encrypted = ciphertext.substr(kNonceSizeInBytes);

    return aead_->Decrypt(encrypted, associated_data, nonce, buffer);
  }

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

 private:
  const std::unique_ptr<SslOneShotAead> aead_;
  const std::string output_prefix_;
};

}  // namespace

absl::StatusOr<std::unique_ptr<ZeroCopyAead>> ChaCha20Poly1305ZeroCopyAead(
    const ChaCha20Poly1305Key& key) {
  ABSL_RETURN_IF_ERROR(
      internal::CheckFipsCompatibility<ZeroCopyChaCha20Poly1305BoringSsl>());
  ABSL_ASSIGN_OR_RETURN(std::unique_ptr<internal::SslOneShotAead> aead,
                        internal::CreateChacha20Poly1305OneShotCrypter(
                            key.GetKeyBytes(GetPartialKeyAccess())
                                .Get(InsecureSecretKeyAccess::Get())));
  return std::make_unique<ZeroCopyChaCha20Poly1305BoringSsl>(
      std::move(aead), key.GetOutputPrefix());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
