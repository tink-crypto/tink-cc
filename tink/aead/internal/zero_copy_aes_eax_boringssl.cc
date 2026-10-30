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

#include "tink/aead/internal/zero_copy_aes_eax_boringssl.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/aead.h"
#include "tink/aead/aes_eax_key.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/secret_data.h"
#include "tink/subtle/random.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

absl::StatusOr<const EVP_AEAD*> GetAesEaxAeadForKeySize(
    size_t key_size_in_bytes) {
  switch (key_size_in_bytes) {
    case 16:
      return EVP_aead_aes_128_eax();
    case 32:
      return EVP_aead_aes_256_eax();
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid key size");
  }
}

bool IsValidNonceSize(size_t nonce_size_in_bytes) {
  return nonce_size_in_bytes == 12 || nonce_size_in_bytes == 16;
}

class AesEaxBoringSslImpl : public internal::ZeroCopyAead {
 public:
  static constexpr int kTagSize = 16;
  static constexpr FipsCompatibility kFipsStatus = FipsCompatibility::kNotFips;

  AesEaxBoringSslImpl(internal::SslUniquePtr<EVP_AEAD_CTX> context,
                      size_t nonce_size, absl::string_view output_prefix = "")
      : context_(std::move(context)),
        nonce_size_(nonce_size),
        output_prefix_(output_prefix) {}

  int64_t MaxEncryptionSize(int64_t plaintext_size) const override {
    return output_prefix_.size() + plaintext_size + nonce_size_ + kTagSize;
  }

  absl::StatusOr<int64_t> Encrypt(absl::string_view plaintext,
                                  absl::string_view associated_data,
                                  absl::Span<char> buffer) const override;

  int64_t MaxDecryptionSize(int64_t ciphertext_size) const override {
    const int64_t overhead = output_prefix_.size() + nonce_size_ + kTagSize;
    if (ciphertext_size < overhead) {
      return 0;
    }
    return ciphertext_size - overhead;
  }

  absl::StatusOr<int64_t> Decrypt(absl::string_view ciphertext,
                                  absl::string_view associated_data,
                                  absl::Span<char> buffer) const override;

 private:
  const internal::SslUniquePtr<EVP_AEAD_CTX> context_;
  const size_t nonce_size_;
  const std::string output_prefix_;
};

absl::StatusOr<int64_t> AesEaxBoringSslImpl::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data,
    absl::Span<char> buffer) const {
  // BoringSSL expects a non-null pointer for plaintext and associated_data,
  // regardless of whether the size is 0.
  plaintext = internal::EnsureStringNonNull(plaintext);
  associated_data = internal::EnsureStringNonNull(associated_data);

  size_t ciphertext_size = MaxEncryptionSize(plaintext.size());
  if (buffer.size() < ciphertext_size) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Encryption buffer too small; expected at least ",
                     ciphertext_size, " bytes, got ", buffer.size()));
  }
  if (internal::BuffersOverlap(
          plaintext, absl::string_view(buffer.data(), buffer.size()))) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Plaintext and output buffer must not overlap");
  }

  return internal::CallWithCoreDumpProtection([&]() -> absl::StatusOr<int64_t> {
    // The ciphertext region is allowed to leak: this never fails and
    // the ciphertext can afterwards be given to the adversary.
    crypto::tink::internal::ScopedAssumeRegionCoreDumpSafe scope_object(
        buffer.data(), ciphertext_size);
    if (!output_prefix_.empty()) {
      std::copy(output_prefix_.begin(), output_prefix_.end(), buffer.begin());
    }
    absl::Span<char> buffer_after_prefix =
        buffer.subspan(output_prefix_.size());
    absl::Span<char> nonce = buffer_after_prefix.subspan(0, nonce_size_);
    ABSL_RETURN_IF_ERROR(subtle::Random::GetRandomBytes(nonce));
    absl::Span<char> raw_ciphertext_and_tag =
        buffer_after_prefix.subspan(nonce_size_, plaintext.size() + kTagSize);
    size_t out_len = 0;
    if (!EVP_AEAD_CTX_seal(
            context_.get(),
            reinterpret_cast<uint8_t*>(raw_ciphertext_and_tag.data()), &out_len,
            raw_ciphertext_and_tag.size(),
            reinterpret_cast<const uint8_t*>(nonce.data()), nonce.size(),
            reinterpret_cast<const uint8_t*>(plaintext.data()),
            plaintext.size(),
            reinterpret_cast<const uint8_t*>(associated_data.data()),
            associated_data.size())) {
      return absl::Status(absl::StatusCode::kInternal, "Encryption failed");
    }
    // Declassify the ciphertext: this is now safe to give to the adversary.
    // (Note: we currently do not propagate labels of the associated data).
    crypto::tink::internal::DfsanClearLabel(buffer.data(), ciphertext_size);
    return ciphertext_size;
  });
}

absl::StatusOr<int64_t> AesEaxBoringSslImpl::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data,
    absl::Span<char> buffer) const {
  // BoringSSL expects a non-null pointer for associated_data,
  // regardless of whether the size is 0.
  associated_data = internal::EnsureStringNonNull(associated_data);

  size_t ct_size = ciphertext.size();
  if (ct_size < output_prefix_.size() + nonce_size_ + kTagSize) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Ciphertext too short");
  }
  size_t out_size = ct_size - output_prefix_.size() - kTagSize - nonce_size_;
  if (buffer.size() < out_size) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Decryption buffer too small; expected at least ",
                     out_size, " bytes, got ", buffer.size()));
  }
  if (internal::BuffersOverlap(
          ciphertext, absl::string_view(buffer.data(), buffer.size()))) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Ciphertext and output buffer must not overlap");
  }
  if (!absl::StartsWith(ciphertext, output_prefix_)) {
    return absl::InvalidArgumentError("Prefix mismatch");
  }
  ciphertext.remove_prefix(output_prefix_.size());
  absl::string_view nonce = ciphertext.substr(0, nonce_size_);
  absl::string_view raw_ciphertext_and_tag = ciphertext.substr(nonce_size_);
  return internal::CallWithCoreDumpProtection([&]() -> absl::StatusOr<int64_t> {
    // The plaintext region is allowed to leak. In successful decryptions,
    // the adversary can already get the plaintext via core dumps (since
    // the API specifies that the plaintext is in a caller-provided buffer,
    // so this is the users responsibility). Hence, this gives adversaries
    // access to data which is stored *during* the computation, and data
    // which would be erased because the tag is wrong. Since EAX is a
    // counter mode, this means that the adversary can potentially obtain
    // key streams for IVs for which he does either not know a valid tag
    // (which seems useless if he didn't see a valid ciphertext) or without
    // querying the actual ciphertext (which does not seem useful). Hence,
    // we declare this to be sufficiently safe at the moment.
    crypto::tink::internal::ScopedAssumeRegionCoreDumpSafe scope_object(
        buffer.data(), out_size);
    // If out_size == 0, buffer.data() may be null or point past the end of an
    // empty buffer; pass a valid 1-byte dummy pointer when calling into
    // BoringSSL.
    uint8_t dummy = 0;
    uint8_t* out_ptr =
        out_size == 0 ? &dummy : reinterpret_cast<uint8_t*>(buffer.data());
    size_t out_len = 0;
    if (!EVP_AEAD_CTX_open(
            context_.get(), out_ptr, &out_len, out_size,
            reinterpret_cast<const uint8_t*>(nonce.data()), nonce.size(),
            reinterpret_cast<const uint8_t*>(raw_ciphertext_and_tag.data()),
            raw_ciphertext_and_tag.size(),
            reinterpret_cast<const uint8_t*>(associated_data.data()),
            associated_data.size())) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Authentication failed");
    }
    // Declassify the plaintext: this is now safe to give to the adversary
    // (since the API specifies that the plaintext is in a caller-provided
    // buffer which can leak so the user is responsible for this).
    crypto::tink::internal::DfsanClearLabel(buffer.data(), out_size);
    return out_size;
  });
}

absl::StatusOr<std::unique_ptr<ZeroCopyAead>> NewZeroCopyAesEaxBoringSsl(
    const SecretData& key, size_t nonce_size_in_bytes,
    absl::string_view output_prefix) {
  ABSL_RETURN_IF_ERROR(
      internal::CheckFipsCompatibility<AesEaxBoringSslImpl>());

  ABSL_ASSIGN_OR_RETURN(const EVP_AEAD* aead,
                        GetAesEaxAeadForKeySize(key.size()));
  if (!IsValidNonceSize(nonce_size_in_bytes)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid nonce size");
  }
  return internal::CallWithCoreDumpProtection(
      [&]() -> absl::StatusOr<std::unique_ptr<ZeroCopyAead>> {
        internal::SslUniquePtr<EVP_AEAD_CTX> context(EVP_AEAD_CTX_new(
            aead, key.data(), key.size(), AesEaxBoringSslImpl::kTagSize));
        if (context == nullptr) {
          return absl::Status(absl::StatusCode::kInternal,
                              "EVP_AEAD_CTX_new failed");
        }
        return std::make_unique<AesEaxBoringSslImpl>(
            std::move(context), nonce_size_in_bytes, output_prefix);
      });
}

}  // namespace

absl::StatusOr<std::unique_ptr<ZeroCopyAead>> AesEaxZeroCopyAead(
    const AesEaxKey& key) {
  if (key.GetParameters().GetTagSizeInBytes() !=
      AesEaxBoringSslImpl::kTagSize) {
    return absl::InvalidArgumentError(
        absl::StrCat("Invalid tag size in bytes; expected ",
                     AesEaxBoringSslImpl::kTagSize, ", got ",
                     key.GetParameters().GetTagSizeInBytes()));
  }
  return NewZeroCopyAesEaxBoringSsl(key.GetKeyBytes(GetPartialKeyAccess())
                                        .Get(InsecureSecretKeyAccess::Get()),
                                    key.GetParameters().GetIvSizeInBytes(),
                                    key.GetOutputPrefix());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
