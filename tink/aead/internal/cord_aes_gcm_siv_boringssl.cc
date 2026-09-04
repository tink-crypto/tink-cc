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

#include "tink/aead/internal/cord_aes_gcm_siv_boringssl.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "absl/strings/cord_buffer.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/opensslv.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/aead.h"
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "tink/aead/aes_gcm_siv_key.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/internal/aead_util.h"
#include "tink/aead/internal/cord_utils.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/err_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/ssl_util.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/subtle/random.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

constexpr int kIvSizeInBytes = 12;
constexpr int kTagSizeInBytes = 16;

absl::Status ValidateMaxBuffers(int num_buffers) {
#ifdef CRYPTO_IOVEC_MAX
  if (num_buffers > CRYPTO_IOVEC_MAX) {
    return absl::InternalError("Too many iovecs, exceeding CRYPTO_IOVEC_MAX");
  }
#endif
  return absl::OkStatus();
}

std::vector<absl::CordBuffer> AllocateCordBuffers(size_t total_size) {
  std::vector<absl::CordBuffer> buffers;
  const size_t max_payload =
      absl::CordBuffer::MaximumPayload(absl::CordBuffer::kCustomLimit);
  if (max_payload > 0) {
    buffers.reserve((total_size + max_payload - 1) / max_payload);
  }
  for (size_t remaining = total_size; remaining > 0;) {
    absl::CordBuffer buf = absl::CordBuffer::CreateWithCustomLimit(
        absl::CordBuffer::kCustomLimit, remaining);
    size_t to_use = std::min(remaining, buf.capacity());
    buf.SetLength(to_use);
    buffers.push_back(std::move(buf));
    remaining -= to_use;
  }
  return buffers;
}

std::vector<CRYPTO_IVEC> BuildAadVecs(const absl::Cord& aad) {
  std::vector<CRYPTO_IVEC> aadvecs;

  for (auto it = aad.chunk_begin(); it != aad.chunk_end(); ++it) {
    absl::string_view chunk = *it;
    if (chunk.empty()) {
      continue;
    }
    aadvecs.push_back(CRYPTO_IVEC{
        reinterpret_cast<const uint8_t*>(chunk.data()),
        chunk.size(),
    });
  }
  return aadvecs;
}

// Constructs a set of BoringSSL IOVECs based on the input Cord and output
// buffers. Each in/out in an IOVEC must be of the same length, hence this
// function splits the input Cord and output buffers into the smallest
// possible chunks that can be used to construct the IOVECs.
std::vector<CRYPTO_IOVEC> BuildIoVecs(
    const absl::Cord& input, absl::Span<absl::CordBuffer> output_buffers) {
  std::vector<CRYPTO_IOVEC> iovecs;
  if (output_buffers.empty()) {
    return iovecs;
  }

  absl::Cord::ChunkIterator chunk_it = input.chunk_begin();
  absl::string_view curr_in_chunk = *chunk_it;

  size_t out_buf_idx = 0;

  absl::Span<char> curr_out_buf = absl::MakeSpan(
      output_buffers[out_buf_idx].data(), output_buffers[out_buf_idx].length());

  while (chunk_it != input.chunk_end() && out_buf_idx < output_buffers.size()) {
    if (curr_in_chunk.empty()) {
      ++chunk_it;
      if (chunk_it != input.chunk_end()) {
        curr_in_chunk = *chunk_it;
      }
      continue;
    }

    if (curr_out_buf.empty()) {
      ++out_buf_idx;
      if (out_buf_idx < output_buffers.size()) {
        curr_out_buf = absl::MakeSpan(output_buffers[out_buf_idx].data(),
                                      output_buffers[out_buf_idx].length());
      }
      continue;
    }

    size_t iov_len = std::min(curr_in_chunk.size(), curr_out_buf.size());
    CRYPTO_IOVEC iov;
    iov.in = reinterpret_cast<const uint8_t*>(curr_in_chunk.data());
    iov.out = reinterpret_cast<uint8_t*>(curr_out_buf.data());
    iov.len = iov_len;
    iovecs.push_back(iov);

    curr_in_chunk.remove_prefix(iov_len);
    curr_out_buf.remove_prefix(iov_len);
  }

  return iovecs;
}

class CordAesGcmSivBoringSsl : public CordAead {
 public:
  explicit CordAesGcmSivBoringSsl(internal::SslUniquePtr<EVP_AEAD_CTX> ctx,
                                  absl::string_view output_prefix)
      : ctx_(std::move(ctx)), output_prefix_(output_prefix) {}

  absl::StatusOr<absl::Cord> Encrypt(
      absl::Cord plaintext, absl::Cord associated_data) const override {
    std::string nonce = subtle::Random::GetRandomBytes(kIvSizeInBytes);

    std::vector<absl::CordBuffer> buffers =
        AllocateCordBuffers(plaintext.size());
    std::vector<CRYPTO_IOVEC> iovecs =
        BuildIoVecs(plaintext, absl::MakeSpan(buffers));
    std::vector<CRYPTO_IVEC> aadvecs = BuildAadVecs(associated_data);

    if (auto status = ValidateMaxBuffers(iovecs.size()); !status.ok()) {
      return status;
    }
    if (auto status = ValidateMaxBuffers(aadvecs.size()); !status.ok()) {
      return status;
    }

    uint8_t tag[kTagSizeInBytes];
    size_t tag_len = 0;

    if (!internal::CallWithCoreDumpProtection([&]() {
          return EVP_AEAD_CTX_sealv(
              ctx_.get(), iovecs.data(), iovecs.size(), tag, &tag_len,
              sizeof(tag), reinterpret_cast<const uint8_t*>(nonce.data()),
              nonce.size(), aadvecs.data(), aadvecs.size());
        })) {
      return absl::InternalError(
          absl::StrCat("Encryption failed: ", internal::GetSslErrors()));
    }

    absl::Cord ciphertext;
    if (!output_prefix_.empty()) {
      ciphertext.Append(output_prefix_);
    }
    ciphertext.Append(std::move(nonce));
    for (auto& buf : buffers) {
      ciphertext.Append(std::move(buf));
    }
    ciphertext.Append(
        absl::string_view(reinterpret_cast<const char*>(tag), tag_len));
    return ciphertext;
  }

  absl::StatusOr<absl::Cord> Decrypt(
      absl::Cord ciphertext, absl::Cord associated_data) const override {
    if (ciphertext.size() <
        output_prefix_.size() + kIvSizeInBytes + kTagSizeInBytes) {
      return absl::InvalidArgumentError("Ciphertext too short");
    }
    if (!output_prefix_.empty()) {
      if (!ciphertext.StartsWith(output_prefix_)) {
        return absl::InvalidArgumentError(
            "Ciphertext does not start with expected prefix");
      }
      ciphertext.RemovePrefix(output_prefix_.size());
    }

    uint8_t nonce[kIvSizeInBytes];
    CordReader(ciphertext)
        .ReadN(kIvSizeInBytes, reinterpret_cast<char*>(nonce));
    ciphertext.RemovePrefix(kIvSizeInBytes);

    absl::Cord tag_cord = ciphertext.Subcord(
        ciphertext.size() - kTagSizeInBytes, kTagSizeInBytes);
    uint8_t tag[kTagSizeInBytes];
    CordReader(tag_cord).ReadN(kTagSizeInBytes, reinterpret_cast<char*>(tag));
    ciphertext.RemoveSuffix(kTagSizeInBytes);

    std::vector<absl::CordBuffer> buffers =
        AllocateCordBuffers(ciphertext.size());

    std::vector<CRYPTO_IOVEC> iovecs =
        BuildIoVecs(ciphertext, absl::MakeSpan(buffers));
    std::vector<CRYPTO_IVEC> aadvecs = BuildAadVecs(associated_data);
    if (auto status = ValidateMaxBuffers(iovecs.size()); !status.ok()) {
      return status;
    }
    if (auto status = ValidateMaxBuffers(aadvecs.size()); !status.ok()) {
      return status;
    }

    if (!internal::CallWithCoreDumpProtection([&]() {
          return EVP_AEAD_CTX_openv_detached(
              ctx_.get(), iovecs.data(), iovecs.size(), nonce, sizeof(nonce),
              tag, sizeof(tag), aadvecs.data(), aadvecs.size());
        })) {
      return absl::InvalidArgumentError("Decryption failed");
    }

    absl::Cord plaintext;
    for (auto& buf : buffers) {
      plaintext.Append(std::move(buf));
    }
    return plaintext;
  }

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

 private:
  internal::SslUniquePtr<EVP_AEAD_CTX> ctx_;
  std::string output_prefix_;
};

absl::StatusOr<std::unique_ptr<CordAead>> New(const SecretData& key,
                                              absl::string_view output_prefix) {
  absl::Status status =
      internal::CheckFipsCompatibility<CordAesGcmSivBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  absl::StatusOr<const EVP_AEAD*> aead_cipher =
      GetAesGcmSivAeadCipherForKeySize(key.size());
  if (!aead_cipher.ok()) {
    return aead_cipher.status();
  }
  bssl::UniquePtr<EVP_AEAD_CTX> ctx(internal::CallWithCoreDumpProtection([&]() {
    return EVP_AEAD_CTX_new(*aead_cipher,
                            reinterpret_cast<const uint8_t*>(key.data()),
                            key.size(), kTagSizeInBytes);
  }));
  if (ctx == nullptr) {
    return absl::InternalError(
        absl::StrCat("EVP_AEAD_CTX_init failed: ", internal::GetSslErrors()));
  }
  return std::make_unique<CordAesGcmSivBoringSsl>(std::move(ctx),
                                                  output_prefix);
}

}  // namespace

absl::StatusOr<std::unique_ptr<CordAead>> NewCordAesGcmSivBoringSsl(
    const SecretData& key, absl::string_view output_prefix) {
  return New(key, output_prefix);
}

absl::StatusOr<std::unique_ptr<CordAead>> NewCordAesGcmSivBoringSsl(
    const AesGcmSivKey& key) {
  return New(key.GetKeyBytes(GetPartialKeyAccess())
                 .Get(InsecureSecretKeyAccess::Get()),
             key.GetOutputPrefix());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#else  // !OPENSSL_IS_BORINGSSL

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<CordAead>> NewCordAesGcmSivBoringSsl(
    const SecretData& key, absl::string_view output_prefix) {
  return absl::Status(absl::StatusCode::kUnimplemented,
                      "AES-GCM-SIV is unimplemented for OpenSSL");
}

absl::StatusOr<std::unique_ptr<CordAead>> NewCordAesGcmSivBoringSsl(
    const AesGcmSivKey& key) {
  return absl::Status(absl::StatusCode::kUnimplemented,
                      "AES-GCM-SIV is unimplemented for OpenSSL");
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // OPENSSL_IS_BORINGSSL
