// Copyright 2021 Google LLC.
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
#include "tink/aead/internal/ssl_aead.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/aead.h"
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "tink/aead/internal/aead_util.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/err_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

ABSL_CONST_INIT const int kXchacha20Poly1305TagSizeInBytes = 16;
ABSL_CONST_INIT const int kAesGcmTagSizeInBytes = 16;
ABSL_CONST_INIT const int kAesGcmSivTagSizeInBytes = 16;

namespace {

// Implementation of the one-shot AEAD cypter. This is purposely internal to
// an anonymous namespace to disallow direct use of this class other than
// through the Create* functions below.
class BoringSslOneShotAeadImpl : public SslOneShotAead {
 public:
  explicit BoringSslOneShotAeadImpl(
      internal::SslUniquePtr<EVP_AEAD_CTX> context, size_t tag_size)
      : context_(std::move(context)), tag_size_(tag_size) {}

  absl::StatusOr<int64_t> Encrypt(absl::string_view plaintext,
                                  absl::string_view associated_data,
                                  absl::string_view iv,
                                  absl::Span<char> out) const override {
    // BoringSSL expects a non-null pointer for associated_data,
    // regardless of whether the size is 0.
    plaintext = internal::EnsureStringNonNull(plaintext);
    associated_data = internal::EnsureStringNonNull(associated_data);
    iv = internal::EnsureStringNonNull(iv);

    if (BuffersOverlap(plaintext, absl::string_view(out.data(), out.size()))) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Plaintext and output buffer must not overlap");
    }

    const int64_t min_out_buff_size = CiphertextSize(plaintext.size());
    ABSL_CHECK_GE(min_out_buff_size, 0);
    if (out.size() < static_cast<size_t>(min_out_buff_size)) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Output buffer too small; expected at least ",
                       min_out_buff_size, " got ", out.size()));
    }
    // The ciphertext will be fine to leak. This assumes that BoringSSL does not
    // use the memory as scratch pad and writes sensitive data into it.
    ScopedAssumeRegionCoreDumpSafe scope_object(out.data(), out.size());
    absl::StatusOr<int64_t> result =
        internal::CallWithCoreDumpProtection([&]() {
          return EncryptSensitive(plaintext, associated_data, iv, out);
        });
    if (!result.ok()) {
      return result;
    }
    // Declassify the ciphertext: it can depend on the key, but that's
    // intentional.
    crypto::tink::internal::DfsanClearLabel(out.data(), out.size());
    return result;
  }

  absl::StatusOr<int64_t> EncryptSensitive(absl::string_view plaintext,
                                           absl::string_view associated_data,
                                           absl::string_view iv,
                                           absl::Span<char> out) const {
    size_t out_len = 0;
    if (!EVP_AEAD_CTX_seal(
            context_.get(), reinterpret_cast<uint8_t *>(&out[0]), &out_len,
            out.size(), reinterpret_cast<const uint8_t *>(iv.data()), iv.size(),
            reinterpret_cast<const uint8_t *>(plaintext.data()),
            plaintext.size(),
            /*ad=*/
            reinterpret_cast<const uint8_t *>(associated_data.data()),
            /*ad_len=*/associated_data.size())) {
      return absl::Status(
          absl::StatusCode::kInternal,
          absl::StrCat("Encryption failed: ", internal::GetSslErrors()));
    }

    return out_len;
  }

  absl::StatusOr<int64_t> Decrypt(absl::string_view ciphertext,
                                  absl::string_view associated_data,
                                  absl::string_view iv,
                                  absl::Span<char> out) const override {
    ciphertext = internal::EnsureStringNonNull(ciphertext);
    associated_data = internal::EnsureStringNonNull(associated_data);
    iv = internal::EnsureStringNonNull(iv);

    if (BuffersOverlap(ciphertext, absl::string_view(out.data(), out.size()))) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Ciphertext and output buffer must not overlap");
    }

    if (ciphertext.size() < tag_size_) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Ciphertext buffer too small; expected at least ",
                       tag_size_, " got ", ciphertext.size()));
    }

    const int64_t min_out_buff_size = PlaintextSize(ciphertext.size());
    ABSL_CHECK_GE(min_out_buff_size, 0);
    if (out.size() < static_cast<size_t>(min_out_buff_size)) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Output buffer too small; expected at least ",
                       min_out_buff_size, " got ", out.size()));
    }

    // We use this for AesGcm, AesGcmSiv, and XChaCha20Poly1305.
    // The following implies that the plaintext region is allowed to leak. In
    // successful decryptions, the adversary can already get the plaintext via
    // core dumps (since the API specifies that the plaintext is in a
    // std::string, so this is the users responsibility). Hence, this gives
    // adversaries access to data which is stored *during* the computation, and
    // data which would be erased because the tag is wrong. Since all algorithms
    // here are using a key stream which depends only on the IV and the key,
    // this means that the adversary can potentially obtain key streams for IVs
    // for which he does either not know a valid tag (which seems useless if he
    // didn't see a valid ciphertext) or without querying the actual ciphertext
    // (which does not seem useful), or very long key streams (longer than for
    // the existing ciphertext). Hence, we declare this to be sufficiently safe
    // at the moment.
    ScopedAssumeRegionCoreDumpSafe scope_object(out.data(), out.size());
    absl::StatusOr<int64_t> result =
        internal::CallWithCoreDumpProtection([&]() {
          return DecryptSensitive(ciphertext, associated_data, iv, out);
        });
    if (!result.ok()) {
      return result;
    }
    // The plaintext is declassified due to the API allowing it to leak.
    crypto::tink::internal::DfsanClearLabel(out.data(), out.size());
    return result;
  }

  absl::StatusOr<int64_t> DecryptSensitive(absl::string_view ciphertext,
                                           absl::string_view associated_data,
                                           absl::string_view iv,
                                           absl::Span<char> out) const {
    // If out.empty() accessing the 0th element would result in an out of
    // bound violation. This makes sure we pass a pointer to at least one byte
    // when calling into OpenSSL.
    uint8_t buffer_if_size_is_zero;
    uint8_t *buffer_ptr = &buffer_if_size_is_zero;
    if (!out.empty()) {
      buffer_ptr = reinterpret_cast<uint8_t *>(&out[0]);
    }

    size_t out_len = 0;
    if (!EVP_AEAD_CTX_open(
            context_.get(), buffer_ptr, &out_len, out.size(),
            reinterpret_cast<const uint8_t *>(iv.data()), iv.size(),
            reinterpret_cast<const uint8_t *>(ciphertext.data()),
            ciphertext.size(),
            /*ad=*/
            reinterpret_cast<const uint8_t *>(associated_data.data()),
            /*ad_len=*/associated_data.size())) {
      return absl::Status(
          absl::StatusCode::kInternal,
          absl::StrCat("Authentication failed: ", internal::GetSslErrors()));
    }

    return out_len;
  }

  int64_t CiphertextSize(int64_t plaintext_length) const override {
    return plaintext_length + tag_size_;
  }

  int64_t PlaintextSize(int64_t ciphertext_length) const override {
    ABSL_CHECK_GE(ciphertext_length, 0);
    if (static_cast<size_t>(ciphertext_length) < tag_size_) {
      return 0;
    }
    return ciphertext_length - tag_size_;
  }

 private:
  const internal::SslUniquePtr<EVP_AEAD_CTX> context_;
  const size_t tag_size_;
};

}  // namespace

absl::StatusOr<std::unique_ptr<SslOneShotAead>> CreateAesGcmOneShotCrypter(
    const SecretData &key) {
  absl::StatusOr<const EVP_AEAD *> aead_cipher =
      GetAesGcmAeadForKeySize(key.size());
  if (!aead_cipher.ok()) {
    return aead_cipher.status();
  }

  internal::SslUniquePtr<EVP_AEAD_CTX> context(
      internal::CallWithCoreDumpProtection([&, aead_cipher = *aead_cipher]() {
        return EVP_AEAD_CTX_new(aead_cipher, key.data(), key.size(),
                                kAesGcmTagSizeInBytes);
      }));
  if (context == nullptr) {
    return absl::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("EVP_AEAD_CTX_new failed: ", internal::GetSslErrors()));
  }
  return {std::make_unique<BoringSslOneShotAeadImpl>(std::move(context),
                                                     kAesGcmTagSizeInBytes)};
}

absl::StatusOr<std::unique_ptr<SslOneShotAead>> CreateAesGcmSivOneShotCrypter(
    const SecretData &key) {
  absl::StatusOr<const EVP_AEAD *> aead_cipher =
      GetAesGcmSivAeadCipherForKeySize(key.size());
  if (!aead_cipher.ok()) {
    return aead_cipher.status();
  }
  internal::SslUniquePtr<EVP_AEAD_CTX> context(
      internal::CallWithCoreDumpProtection([&, aead_cipher = *aead_cipher]() {
        return EVP_AEAD_CTX_new(aead_cipher, key.data(), key.size(),
                                kAesGcmTagSizeInBytes);
      }));
  if (context == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        absl::StrCat("EVP_AEAD_CTX_new initialization Failed: ",
                                     internal::GetSslErrors()));
  }
  return {std::make_unique<BoringSslOneShotAeadImpl>(std::move(context),
                                                     kAesGcmSivTagSizeInBytes)};
}

absl::StatusOr<std::unique_ptr<SslOneShotAead>>
CreateXchacha20Poly1305OneShotCrypter(const SecretData &key) {
  if (key.size() != 32) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid key size; valid values are {32} bytes, got ",
                     key.size()));
  }

  internal::SslUniquePtr<EVP_AEAD_CTX> context(
      internal::CallWithCoreDumpProtection([&]() {
        return EVP_AEAD_CTX_new(EVP_aead_xchacha20_poly1305(), key.data(),
                                key.size(), kAesGcmTagSizeInBytes);
      }));
  if (context == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        absl::StrCat("EVP_AEAD_CTX_new initialization Failed: ",
                                     internal::GetSslErrors()));
  }
  return {std::make_unique<BoringSslOneShotAeadImpl>(
      std::move(context), kXchacha20Poly1305TagSizeInBytes)};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
