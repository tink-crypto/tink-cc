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

#include "tink/aead/internal/zero_copy_xchacha20_poly1305_boringssl.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead/internal/ssl_aead.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/util.h"
#include "tink/secret_data.h"
#include "tink/subtle/random.h"

namespace crypto {
namespace tink {
namespace internal {

constexpr int kNonceSizeInBytes = 24;
constexpr int kTagSizeInBytes = 16;
constexpr int kOverheadInBytes = kNonceSizeInBytes + kTagSizeInBytes;

absl::StatusOr<std::unique_ptr<ZeroCopyAead>>
ZeroCopyXChacha20Poly1305BoringSsl::New(SecretData key) {
  auto status =
      internal::CheckFipsCompatibility<ZeroCopyXChacha20Poly1305BoringSsl>();
  if (!status.ok()) {
    return status;
  }
  absl::StatusOr<std::unique_ptr<internal::SslOneShotAead>> aead =
      internal::CreateXchacha20Poly1305OneShotCrypter(key);
  if (!aead.ok()) {
    return aead.status();
  }
  std::unique_ptr<ZeroCopyAead> aead_impl = absl::WrapUnique(
      new ZeroCopyXChacha20Poly1305BoringSsl(*std::move(aead)));
  return std::move(aead_impl);
}

int64_t ZeroCopyXChacha20Poly1305BoringSsl::MaxEncryptionSize(
    int64_t plaintext_size) const {
  // No need to call `aead_->CiphertextSize()` here as the overhead is known.
  return plaintext_size + kOverheadInBytes;
}

absl::StatusOr<int64_t> ZeroCopyXChacha20Poly1305BoringSsl::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data,
    absl::Span<char> buffer) const {
  size_t bytes_needed = plaintext.size() + kOverheadInBytes;
  if (buffer.size() < bytes_needed) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Encryption buffer too small; expected at least ",
                     bytes_needed, " bytes, got ", buffer.size()));
  }

  absl::string_view buffer_string(buffer.data(), buffer.size());
  if (BuffersOverlap(plaintext, buffer_string)) {
    return absl::Status(
        absl::StatusCode::kFailedPrecondition,
        "Plaintext and ciphertext buffers overlap; this is disallowed");
  }

  absl::Span<char> nonce_buffer = buffer.subspan(0, kNonceSizeInBytes);
  absl::Span<char> encrypted_buffer = buffer.subspan(kNonceSizeInBytes);

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
  return kNonceSizeInBytes + *written_bytes;
}

int64_t ZeroCopyXChacha20Poly1305BoringSsl::MaxDecryptionSize(
    int64_t ciphertext_size) const {
  // No need to call `aead_->PlaintextSize()` here as the overhead is known.
  if (ciphertext_size < kOverheadInBytes) {
    return 0;
  }
  return ciphertext_size - kOverheadInBytes;
}

absl::StatusOr<int64_t> ZeroCopyXChacha20Poly1305BoringSsl::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data,
    absl::Span<char> buffer) const {
  if (ciphertext.size() < kOverheadInBytes) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Ciphertext too short; expected at least ",
                     kOverheadInBytes, " got ", ciphertext.size()));
  }

  absl::string_view buffer_string(buffer.data(), buffer.size());
  if (BuffersOverlap(ciphertext, buffer_string)) {
    return absl::Status(
        absl::StatusCode::kFailedPrecondition,
        "Plaintext and ciphertext buffers overlap; this is disallowed");
  }

  absl::string_view nonce = ciphertext.substr(0, kNonceSizeInBytes);
  absl::string_view encrypted = ciphertext.substr(kNonceSizeInBytes);

  return aead_->Decrypt(encrypted, associated_data, nonce, buffer);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
