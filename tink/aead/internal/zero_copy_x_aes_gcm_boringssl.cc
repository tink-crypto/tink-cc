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

#include "tink/aead/internal/zero_copy_x_aes_gcm_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

#include "absl/log/absl_check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead/internal/base_x_aes_gcm.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/aead/internal/zero_copy_aes_gcm_boringssl.h"
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/secret_data.h"
#include "tink/subtle/random.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::subtle::Random;

class XAesGcmBoringSslZeroCopyAead : public ZeroCopyAead {
 public:
  explicit XAesGcmBoringSslZeroCopyAead(BaseXAesGcm base_x_aes_gcm)
      : base_x_aes_gcm_(std::move(base_x_aes_gcm)) {}

  int64_t MaxEncryptionSize(int64_t plaintext_size) const override {
    return base_x_aes_gcm_.min_ct_size() + plaintext_size;
  }

  absl::StatusOr<int64_t> Encrypt(absl::string_view plaintext,
                                  absl::string_view associated_data,
                                  absl::Span<char> buffer) const override {
    const int64_t max_encryption_size = MaxEncryptionSize(plaintext.size());
    ABSL_CHECK_GE(max_encryption_size, 0);
    if (buffer.size() < static_cast<size_t>(max_encryption_size)) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Encryption buffer too small; expected at least ",
                       max_encryption_size, " bytes, got ", buffer.size()));
    }
    absl::Status status =
        Random::GetRandomBytes(buffer.subspan(0, base_x_aes_gcm_.salt_size()));
    if (!status.ok()) {
      return status;
    }
    absl::StatusOr<SecretData> derived_key =
        base_x_aes_gcm_.DerivePerMessageKey(
            absl::string_view(buffer.data(), base_x_aes_gcm_.salt_size()));
    if (!derived_key.ok()) {
      return derived_key.status();
    }
    absl::StatusOr<std::unique_ptr<ZeroCopyAead>> zero_copy_aead =
        ZeroCopyAesGcmBoringSsl::New(*derived_key);
    if (!zero_copy_aead.ok()) {
      return zero_copy_aead.status();
    }
    absl::StatusOr<int64_t> written_bytes =
        (*zero_copy_aead)
            ->Encrypt(plaintext, associated_data,
                      buffer.subspan(base_x_aes_gcm_.salt_size()));
    if (!written_bytes.ok()) {
      return written_bytes.status();
    }
    return base_x_aes_gcm_.salt_size() + *written_bytes;
  }

  int64_t MaxDecryptionSize(int64_t ciphertext_size) const override {
    const int64_t size = ciphertext_size - base_x_aes_gcm_.min_ct_size();
    if (size <= 0) {
      return 0;
    }
    return size;
  }

  absl::StatusOr<int64_t> Decrypt(absl::string_view ciphertext,
                                  absl::string_view associated_data,
                                  absl::Span<char> buffer) const override {
    const int min_ct_size = base_x_aes_gcm_.min_ct_size();
    ABSL_CHECK_GE(min_ct_size, 0);
    if (ciphertext.size() < static_cast<size_t>(min_ct_size)) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Ciphertext too short; expected at least ",
                       min_ct_size, " bytes, got ", ciphertext.size()));
    }
    const int max_decryption_size = MaxDecryptionSize(ciphertext.size());
    ABSL_CHECK_GE(max_decryption_size, 0);
    if (buffer.size() < static_cast<size_t>(max_decryption_size)) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Decryption buffer too small; expected at least ",
                       MaxDecryptionSize(ciphertext.size()), " bytes, got ",
                       buffer.size()));
    }
    absl::StatusOr<SecretData> derived_key =
        base_x_aes_gcm_.DerivePerMessageKey(
            ciphertext.substr(0, base_x_aes_gcm_.salt_size()));
    if (!derived_key.ok()) {
      return derived_key.status();
    }
    absl::StatusOr<std::unique_ptr<ZeroCopyAead>> zero_copy_aead =
        ZeroCopyAesGcmBoringSsl::New(*derived_key);
    if (!zero_copy_aead.ok()) {
      return zero_copy_aead.status();
    }
    return (*zero_copy_aead)
        ->Decrypt(ciphertext.substr(base_x_aes_gcm_.salt_size()),
                  associated_data, buffer);
  }

 private:
  BaseXAesGcm base_x_aes_gcm_;
};

}  // namespace

absl::StatusOr<std::unique_ptr<ZeroCopyAead>> NewZeroCopyXAesGcmBoringSsl(
    const XAesGcmKey& key) {
  absl::StatusOr<BaseXAesGcm> base_x_aes_gcm = BaseXAesGcm::New(key);
  if (!base_x_aes_gcm.ok()) {
    return base_x_aes_gcm.status();
  }
  return absl::make_unique<XAesGcmBoringSslZeroCopyAead>(
      *std::move(base_x_aes_gcm));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
