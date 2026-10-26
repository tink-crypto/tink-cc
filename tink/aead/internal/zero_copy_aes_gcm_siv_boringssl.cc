// Copyright 2018 Google Inc.
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

#include "tink/aead/internal/zero_copy_aes_gcm_siv_boringssl.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/log/absl_check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead/aes_gcm_siv_key.h"
#include "tink/aead/internal/ssl_aead.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/secret_data.h"
#include "tink/subtle/random.h"

namespace crypto {
namespace tink {
namespace internal {

constexpr int kNonceSizeInBytes = 12;
constexpr int kTagSizeInBytes = 16;
constexpr int kOverheadInBytes = kNonceSizeInBytes + kTagSizeInBytes;

absl::StatusOr<std::unique_ptr<ZeroCopyAead>> ZeroCopyAesGcmSivBoringSsl::New(
    const SecretData& key) {
  auto status = internal::CheckFipsCompatibility<ZeroCopyAesGcmSivBoringSsl>();
  if (!status.ok()) {
    return status;
  }
  absl::StatusOr<std::unique_ptr<internal::SslOneShotAead>> aead =
      internal::CreateAesGcmSivOneShotCrypter(key);
  if (!aead.ok()) {
    return aead.status();
  }

  return {absl::WrapUnique(new ZeroCopyAesGcmSivBoringSsl(*std::move(aead)))};
}

absl::StatusOr<std::unique_ptr<ZeroCopyAead>> ZeroCopyAesGcmSivBoringSsl::New(
    const AesGcmSivKey& key) {
  auto status = internal::CheckFipsCompatibility<ZeroCopyAesGcmSivBoringSsl>();
  if (!status.ok()) {
    return status;
  }
  absl::StatusOr<std::unique_ptr<internal::SslOneShotAead>> aead =
      internal::CreateAesGcmSivOneShotCrypter(
          key.GetKeyBytes(GetPartialKeyAccess())
              .Get(InsecureSecretKeyAccess::Get()));
  if (!aead.ok()) {
    return aead.status();
  }

  return {absl::WrapUnique(new ZeroCopyAesGcmSivBoringSsl(
      *std::move(aead), key.GetOutputPrefix()))};
}

int64_t ZeroCopyAesGcmSivBoringSsl::MaxEncryptionSize(
    int64_t plaintext_size) const {
  // No need to call `aead_->CiphertextSize()` here as the overhead is known.
  return output_prefix_.size() + plaintext_size + kOverheadInBytes;
}

absl::StatusOr<int64_t> ZeroCopyAesGcmSivBoringSsl::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data,
    absl::Span<char> buffer) const {
  const int64_t max_encryption_size = MaxEncryptionSize(plaintext.size());
  ABSL_CHECK_GE(max_encryption_size, 0);
  if (buffer.size() < static_cast<size_t>(max_encryption_size)) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Encryption buffer too small; expected at least ",
                     max_encryption_size, " bytes, got ", buffer.size()));
  }

  absl::string_view buffer_string(buffer.data(), buffer.size());
  if (BuffersOverlap(plaintext, buffer_string)) {
    return absl::Status(
        absl::StatusCode::kFailedPrecondition,
        "Plaintext and ciphertext buffers overlap; this is disallowed");
  }

  if (!output_prefix_.empty()) {
    std::copy(output_prefix_.begin(), output_prefix_.end(), buffer.begin());
  }

  absl::Span<char> buffer_after_prefix = buffer.subspan(output_prefix_.size());
  absl::Span<char> nonce_buffer =
      buffer_after_prefix.subspan(0, kNonceSizeInBytes);
  absl::Span<char> encrypted_buffer =
      buffer_after_prefix.subspan(kNonceSizeInBytes);

  absl::Status res = subtle::Random::GetRandomBytes(nonce_buffer);
  if (!res.ok()) {
    return res;
  }
  absl::StatusOr<int64_t> written_bytes = aead_->Encrypt(
      plaintext, associated_data,
      absl::string_view(nonce_buffer.data(), nonce_buffer.size()),
      encrypted_buffer);
  if (!written_bytes.ok()) {
    return written_bytes.status();
  }
  return output_prefix_.size() + kNonceSizeInBytes + *written_bytes;
}

int64_t ZeroCopyAesGcmSivBoringSsl::MaxDecryptionSize(
    int64_t ciphertext_size) const {
  // No need to call `aead_->PlaintextSize()` here as the overhead is known.
  const int64_t size =
      ciphertext_size - output_prefix_.size() - kOverheadInBytes;
  if (size <= 0) {
    return 0;
  }
  return size;
}

absl::StatusOr<int64_t> ZeroCopyAesGcmSivBoringSsl::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data,
    absl::Span<char> buffer) const {
  const size_t min_ciphertext_size = output_prefix_.size() + kOverheadInBytes;
  if (ciphertext.size() < min_ciphertext_size) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Ciphertext too short; expected at least ",
                     min_ciphertext_size, " got ", ciphertext.size()));
  }

  const int64_t max_decryption_size = MaxDecryptionSize(ciphertext.size());
  ABSL_CHECK_GE(max_decryption_size, 0);
  if (buffer.size() < static_cast<size_t>(max_decryption_size)) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Decryption buffer too small; expected at least ",
                     max_decryption_size, " bytes, got ", buffer.size()));
  }

  absl::string_view buffer_string(buffer.data(), buffer.size());
  if (BuffersOverlap(ciphertext, buffer_string)) {
    return absl::Status(
        absl::StatusCode::kFailedPrecondition,
        "Plaintext and ciphertext buffers overlap; this is disallowed");
  }

  if (!output_prefix_.empty()) {
    if (!absl::StartsWith(ciphertext, output_prefix_)) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Prefix mismatch");
    }
    ciphertext.remove_prefix(output_prefix_.size());
  }

  absl::string_view nonce = ciphertext.substr(0, kNonceSizeInBytes);
  absl::string_view encrypted = ciphertext.substr(kNonceSizeInBytes);

  return aead_->Decrypt(encrypted, associated_data, nonce, buffer);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
