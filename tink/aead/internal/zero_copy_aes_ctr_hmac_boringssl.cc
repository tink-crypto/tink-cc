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

#include "tink/aead/internal/zero_copy_aes_ctr_hmac_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <utility>

#include "absl/log/absl_check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "tink/aead/aes_ctr_hmac_aead_key.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/aes_util.h"
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

constexpr int kMinIvSizeInBytes = 12;
constexpr size_t kMinHmacKeySizeInBytes = 16;
constexpr int kMinTagSizeInBytes = 10;

void StoreBigEndian64(uint8_t out[8], uint64_t value) {
  for (int i = 7; i >= 0; --i) {
    out[i] = static_cast<uint8_t>(value & 0xff);
    value >>= 8;
  }
}

absl::StatusOr<const EVP_MD*> EvpMdFromHashType(
    AesCtrHmacAeadParameters::HashType hash_type) {
  switch (hash_type) {
    case AesCtrHmacAeadParameters::HashType::kSha1:
      return EVP_sha1();
    case AesCtrHmacAeadParameters::HashType::kSha224:
      return EVP_sha224();
    case AesCtrHmacAeadParameters::HashType::kSha256:
      return EVP_sha256();
    case AesCtrHmacAeadParameters::HashType::kSha384:
      return EVP_sha384();
    case AesCtrHmacAeadParameters::HashType::kSha512:
      return EVP_sha512();
    default:
      return absl::Status(absl::StatusCode::kUnimplemented,
                          "Unsupported hash type");
  }
}

}  // namespace

absl::StatusOr<std::unique_ptr<ZeroCopyAead>> ZeroCopyAesCtrHmacBoringSsl::New(
    const AesCtrHmacAeadKey& key) {
  ABSL_RETURN_IF_ERROR(
      internal::CheckFipsCompatibility<ZeroCopyAesCtrHmacBoringSsl>());

  const SecretData& aes_key = key.GetAesKeyBytes(GetPartialKeyAccess())
                                  .Get(InsecureSecretKeyAccess::Get());
  int iv_size = key.GetParameters().GetIvSizeInBytes();
  if (iv_size < kMinIvSizeInBytes || iv_size > internal::AesBlockSize()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid IV size: ", iv_size,
                     " bytes; must be between 12 and 16 bytes"));
  }
  ABSL_ASSIGN_OR_RETURN(const EVP_CIPHER* cipher,
                        internal::GetAesCtrCipherForKeySize(aes_key.size()));

  const SecretData& hmac_key = key.GetHmacKeyBytes(GetPartialKeyAccess())
                                   .Get(InsecureSecretKeyAccess::Get());
  if (hmac_key.size() < kMinHmacKeySizeInBytes) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid HMAC key size: must be at least 16 bytes");
  }
  ABSL_ASSIGN_OR_RETURN(const EVP_MD* md,
                        EvpMdFromHashType(key.GetParameters().GetHashType()));
  int tag_size = key.GetParameters().GetTagSizeInBytes();
  if (tag_size < kMinTagSizeInBytes ||
      static_cast<size_t>(tag_size) > EVP_MD_size(md)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid HMAC tag size");
  }

  internal::SslUniquePtr<EVP_CIPHER_CTX> base_aes_ctx(EVP_CIPHER_CTX_new());
  if (base_aes_ctx == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Failed to allocate EVP_CIPHER_CTX");
  }
  internal::SslUniquePtr<HMAC_CTX> base_hmac_ctx(HMAC_CTX_new());
  if (base_hmac_ctx == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Failed to allocate HMAC_CTX");
  }

  absl::Status init_status =
      internal::CallWithCoreDumpProtection([&]() -> absl::Status {
        if (EVP_CipherInit_ex(base_aes_ctx.get(), cipher, /*impl=*/nullptr,
                              aes_key.data(), /*iv=*/nullptr,
                              /*enc=*/1) != 1) {
          return absl::Status(absl::StatusCode::kInternal,
                              "Failed to initialize EVP_CIPHER_CTX");
        }
        if (HMAC_Init_ex(base_hmac_ctx.get(), hmac_key.data(), hmac_key.size(),
                         md, /*impl=*/nullptr) != 1) {
          return absl::Status(absl::StatusCode::kInternal,
                              "Failed to initialize HMAC_CTX");
        }
        return absl::OkStatus();
      });
  ABSL_RETURN_IF_ERROR(init_status);

  return absl::WrapUnique(new ZeroCopyAesCtrHmacBoringSsl(
      std::move(base_aes_ctx), std::move(base_hmac_ctx), iv_size, tag_size,
      key.GetOutputPrefix()));
}

int64_t ZeroCopyAesCtrHmacBoringSsl::MaxEncryptionSize(
    int64_t plaintext_size) const {
  return static_cast<int64_t>(output_prefix_.size()) + iv_size_ +
         plaintext_size + tag_size_;
}

int64_t ZeroCopyAesCtrHmacBoringSsl::MaxDecryptionSize(
    int64_t ciphertext_size) const {
  const int64_t overhead =
      static_cast<int64_t>(output_prefix_.size()) + iv_size_ + tag_size_;
  if (ciphertext_size <= overhead) {
    return 0;
  }
  return ciphertext_size - overhead;
}

absl::StatusOr<int64_t> ZeroCopyAesCtrHmacBoringSsl::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data,
    absl::Span<char> buffer) const {
  if (plaintext.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Plaintext too large");
  }
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

  const uint64_t aad_size_bits =
      static_cast<uint64_t>(associated_data.size()) * 8;
  if (aad_size_bits / 8 != associated_data.size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "associated_data is too long");
  }

  if (!output_prefix_.empty()) {
    std::memcpy(buffer.data(), output_prefix_.data(), output_prefix_.size());
  }

  ABSL_RETURN_IF_ERROR(subtle::Random::GetRandomBytes(
      buffer.subspan(output_prefix_.size(), iv_size_)));

  uint8_t iv_block[internal::AesBlockSize()] = {0};
  std::memcpy(iv_block, buffer.data() + output_prefix_.size(), iv_size_);

  plaintext = internal::EnsureStringNonNull(plaintext);
  associated_data = internal::EnsureStringNonNull(associated_data);

  uint8_t aad_bits_be[8];
  StoreBigEndian64(aad_bits_be, aad_size_bits);

  uint8_t* raw_ct_ptr = reinterpret_cast<uint8_t*>(
      buffer.data() + output_prefix_.size() + iv_size_);
  const uint8_t* payload_ptr =
      reinterpret_cast<const uint8_t*>(buffer.data() + output_prefix_.size());
  const size_t payload_size = iv_size_ + plaintext.size();

  internal::ScopedAssumeRegionCoreDumpSafe scope_out(
      raw_ct_ptr, plaintext.size() + tag_size_);

  absl::Status status =
      internal::CallWithCoreDumpProtection([&]() -> absl::Status {
        if (!plaintext.empty()) {
#ifdef OPENSSL_IS_BORINGSSL
          bssl::ScopedEVP_CIPHER_CTX aes_ctx;
#else
          internal::SslUniquePtr<EVP_CIPHER_CTX> aes_ctx(EVP_CIPHER_CTX_new());
          if (aes_ctx == nullptr) {
            return absl::Status(absl::StatusCode::kInternal,
                                "Failed to allocate EVP_CIPHER_CTX");
          }
#endif
          if (EVP_CIPHER_CTX_copy(aes_ctx.get(), base_aes_ctx_.get()) != 1) {
            return absl::Status(absl::StatusCode::kInternal,
                                "EVP_CIPHER_CTX_copy failed");
          }
          if (EVP_CipherInit_ex(aes_ctx.get(), /*cipher=*/nullptr,
                                /*impl=*/nullptr, /*key=*/nullptr, iv_block,
                                /*enc=*/-1) != 1) {
            return absl::Status(absl::StatusCode::kInternal,
                                "EVP_CipherInit_ex failed");
          }
          int out_len = 0;
          if (EVP_CipherUpdate(
                  aes_ctx.get(), raw_ct_ptr, &out_len,
                  reinterpret_cast<const uint8_t*>(plaintext.data()),
                  static_cast<int>(plaintext.size())) != 1 ||
              static_cast<size_t>(out_len) != plaintext.size()) {
            return absl::Status(absl::StatusCode::kInternal,
                                "EVP_CipherUpdate failed");
          }
        }

#ifdef OPENSSL_IS_BORINGSSL
        bssl::ScopedHMAC_CTX hmac_ctx;
        if (HMAC_CTX_copy_ex(hmac_ctx.get(), base_hmac_ctx_.get()) != 1) {
          return absl::Status(absl::StatusCode::kInternal,
                              "HMAC_CTX_copy_ex failed");
        }
#else
        internal::SslUniquePtr<HMAC_CTX> hmac_ctx(HMAC_CTX_new());
        if (hmac_ctx == nullptr) {
          return absl::Status(absl::StatusCode::kInternal,
                              "Failed to allocate HMAC_CTX");
        }
        if (HMAC_CTX_copy(hmac_ctx.get(), base_hmac_ctx_.get()) != 1) {
          return absl::Status(absl::StatusCode::kInternal,
                              "HMAC_CTX_copy failed");
        }
#endif
        if (HMAC_Update(
                hmac_ctx.get(),
                reinterpret_cast<const uint8_t*>(associated_data.data()),
                associated_data.size()) != 1 ||
            HMAC_Update(hmac_ctx.get(), payload_ptr, payload_size) != 1 ||
            HMAC_Update(hmac_ctx.get(), aad_bits_be, sizeof(aad_bits_be)) !=
                1) {
          return absl::Status(absl::StatusCode::kInternal,
                              "HMAC_Update failed");
        }
        uint8_t tag_buf[EVP_MAX_MD_SIZE];
        unsigned int tag_len = 0;
        if (HMAC_Final(hmac_ctx.get(), tag_buf, &tag_len) != 1) {
          OPENSSL_cleanse(tag_buf, sizeof(tag_buf));
          return absl::Status(absl::StatusCode::kInternal, "HMAC_Final failed");
        }
        std::memcpy(raw_ct_ptr + plaintext.size(), tag_buf, tag_size_);
        OPENSSL_cleanse(tag_buf, sizeof(tag_buf));
        return absl::OkStatus();
      });
  ABSL_RETURN_IF_ERROR(status);

  // Declassify the ciphertext: it can depend on the key, but that's
  // intentional.
  internal::DfsanClearLabel(raw_ct_ptr, plaintext.size() + tag_size_);
  return max_encryption_size;
}

absl::StatusOr<int64_t> ZeroCopyAesCtrHmacBoringSsl::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data,
    absl::Span<char> buffer) const {
  const size_t min_ciphertext_size =
      output_prefix_.size() + iv_size_ + tag_size_;
  if (ciphertext.size() < min_ciphertext_size) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Ciphertext too short; expected at least ",
                     min_ciphertext_size, " bytes, got ", ciphertext.size()));
  }
  if (ciphertext.size() - min_ciphertext_size >
      static_cast<size_t>(std::numeric_limits<int>::max())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Ciphertext too large");
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

  const uint64_t aad_size_bits =
      static_cast<uint64_t>(associated_data.size()) * 8;
  if (aad_size_bits / 8 != associated_data.size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "associated_data is too long");
  }

  if (!output_prefix_.empty()) {
    if (!absl::StartsWith(ciphertext, output_prefix_)) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Prefix mismatch");
    }
    ciphertext.remove_prefix(output_prefix_.size());
  }

  absl::string_view payload =
      ciphertext.substr(0, ciphertext.size() - tag_size_);
  absl::string_view tag =
      ciphertext.substr(ciphertext.size() - tag_size_, tag_size_);
  associated_data = internal::EnsureStringNonNull(associated_data);

  uint8_t aad_bits_be[8];
  StoreBigEndian64(aad_bits_be, aad_size_bits);

  uint8_t iv_block[internal::AesBlockSize()] = {0};
  std::memcpy(iv_block, payload.data(), iv_size_);
  absl::string_view raw_ciphertext =
      internal::EnsureStringNonNull(payload.substr(iv_size_));

  ScopedAssumeRegionCoreDumpSafe scope_pt(buffer.data(), raw_ciphertext.size());
  absl::Status decrypt_status =
      internal::CallWithCoreDumpProtection([&]() -> absl::Status {
        uint8_t tag_buf[EVP_MAX_MD_SIZE];
#ifdef OPENSSL_IS_BORINGSSL
        bssl::ScopedHMAC_CTX hmac_ctx;
        if (HMAC_CTX_copy_ex(hmac_ctx.get(), base_hmac_ctx_.get()) != 1) {
          return absl::Status(absl::StatusCode::kInternal,
                              "HMAC_CTX_copy_ex failed");
        }
#else
        internal::SslUniquePtr<HMAC_CTX> hmac_ctx(HMAC_CTX_new());
        if (hmac_ctx == nullptr) {
          return absl::Status(absl::StatusCode::kInternal,
                              "Failed to allocate HMAC_CTX");
        }
        if (HMAC_CTX_copy(hmac_ctx.get(), base_hmac_ctx_.get()) != 1) {
          return absl::Status(absl::StatusCode::kInternal,
                              "HMAC_CTX_copy failed");
        }
#endif
        if (HMAC_Update(
                hmac_ctx.get(),
                reinterpret_cast<const uint8_t*>(associated_data.data()),
                associated_data.size()) != 1 ||
            HMAC_Update(hmac_ctx.get(),
                        reinterpret_cast<const uint8_t*>(payload.data()),
                        payload.size()) != 1 ||
            HMAC_Update(hmac_ctx.get(), aad_bits_be, sizeof(aad_bits_be)) !=
                1) {
          return absl::Status(absl::StatusCode::kInternal,
                              "HMAC_Update failed");
        }
        unsigned int tag_len = 0;
        if (HMAC_Final(hmac_ctx.get(), tag_buf, &tag_len) != 1) {
          OPENSSL_cleanse(tag_buf, sizeof(tag_buf));
          return absl::Status(absl::StatusCode::kInternal, "HMAC_Final failed");
        }
        bool mac_ok =
            internal::SafeCryptoMemEquals(tag_buf, tag.data(), tag_size_);
        internal::CutAllFlows(mac_ok);
        OPENSSL_cleanse(tag_buf, sizeof(tag_buf));
        if (!mac_ok) {
          return absl::Status(absl::StatusCode::kInvalidArgument,
                              "Verification failed");
        }

        if (!raw_ciphertext.empty()) {
#ifdef OPENSSL_IS_BORINGSSL
          bssl::ScopedEVP_CIPHER_CTX aes_ctx;
#else
          internal::SslUniquePtr<EVP_CIPHER_CTX> aes_ctx(EVP_CIPHER_CTX_new());
          if (aes_ctx == nullptr) {
            return absl::Status(absl::StatusCode::kInternal,
                                "Failed to allocate EVP_CIPHER_CTX");
          }
#endif
          if (EVP_CIPHER_CTX_copy(aes_ctx.get(), base_aes_ctx_.get()) != 1) {
            return absl::Status(absl::StatusCode::kInternal,
                                "EVP_CIPHER_CTX_copy failed");
          }
          if (EVP_CipherInit_ex(aes_ctx.get(), /*cipher=*/nullptr,
                                /*impl=*/nullptr, /*key=*/nullptr, iv_block,
                                /*enc=*/-1) != 1) {
            return absl::Status(absl::StatusCode::kInternal,
                                "EVP_CipherInit_ex failed");
          }
          int out_len = 0;
          if (EVP_CipherUpdate(
                  aes_ctx.get(), reinterpret_cast<uint8_t*>(buffer.data()),
                  &out_len,
                  reinterpret_cast<const uint8_t*>(raw_ciphertext.data()),
                  static_cast<int>(raw_ciphertext.size())) != 1 ||
              static_cast<size_t>(out_len) != raw_ciphertext.size()) {
            return absl::Status(absl::StatusCode::kInternal,
                                "EVP_CipherUpdate failed");
          }
        }
        return absl::OkStatus();
      });
  if (!decrypt_status.ok()) {
    if (!buffer.empty()) {
      OPENSSL_cleanse(buffer.data(), buffer.size());
    }
    return decrypt_status;
  }

  internal::DfsanClearLabel(buffer.data(), raw_ciphertext.size());
  return raw_ciphertext.size();
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
