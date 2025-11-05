// Copyright 2020 Google LLC
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

#include "tink/aead/internal/cord_aes_gcm_boringssl.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/cord.h"
#include "absl/strings/cord_buffer.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/cipher.h"
#else
#include "openssl/evp.h"
#endif
#include "tink/aead/cord_aead.h"
#include "tink/aead/internal/aead_util.h"
#include "tink/aead/internal/cord_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

constexpr int kIvSizeInBytes = 12;
constexpr int kTagSizeInBytes = 16;

// Encrypt/decrypt at most `kMaxSegmentSize` bytes at a time, then attempt to
// remove the processed segment from the Cord.
constexpr int kMaxSegmentSize = 512 << 10;  // 512 KiB

// Set the IV `iv` for the given `context`. if `encryption` is true, set the
// context for encryption, and for decryption otherwise.
absl::Status SetIvAndDirection(EVP_CIPHER_CTX* context, absl::string_view iv,
                               bool encryption) {
  const int encryption_flag = encryption ? 1 : 0;
  // Set the IV size.
  if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, iv.size(),
                          /*ptr=*/nullptr) <= 0) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Failed to set the IV size");
  }
  // Finally set the IV bytes.
  if (EVP_CipherInit_ex(context, /*cipher=*/nullptr, /*engine=*/nullptr,
                        /*key=*/nullptr,
                        reinterpret_cast<const uint8_t*>(&iv[0]),
                        /*enc=*/encryption_flag) <= 0) {
    return absl::Status(absl::StatusCode::kInternal, "Failed to set the IV");
  }

  return absl::OkStatus();
}

#if defined(OPENSSL_IS_BORINGSSL) || OPENSSL_VERSION_NUMBER < 0x30000000L
// Returns a new EVP_CIPHER_CTX for encryption (`encryption` == true) or
// decryption (`encryption` == false). It tries to skip part of the
// initialization copying `partial_context`.
absl::StatusOr<internal::SslUniquePtr<EVP_CIPHER_CTX>> NewContextFromPartial(
    EVP_CIPHER_CTX* partial_context, absl::string_view iv, bool encryption) {
  internal::SslUniquePtr<EVP_CIPHER_CTX> context(EVP_CIPHER_CTX_new());
  if (context == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "EVP_CIPHER_CTX_new failed");
  }
  // Try making a copy of `partial_context` to skip some pre-computations.
  //
  // NOTE: With BoringSSL and OpenSSL 1.1.1 EVP_CIPHER_CTX_copy makes a copy
  // of the `cipher_data` field of `context` as well, which contains the key
  // material and IV (see [1] and [2]).
  //
  // [1]https://github.com/google/boringssl/blob/4c8bcf0da2951cacd8ed8eaa7fd2df4b22fca23b/crypto/fipsmodule/cipher/cipher.c#L116
  // [2]https://github.com/openssl/openssl/blob/830bf8e1e4749ad65c51b6a1d0d769ae689404ba/crypto/evp/evp_enc.c#L703
  if (EVP_CIPHER_CTX_copy(context.get(), partial_context) <= 0) {
    return absl::Status(absl::StatusCode::kInternal,
                        "EVP_CIPHER_CTX_copy failed");
  }
  absl::Status res =
      SetIvAndDirection(context.get(), iv, /*encryption=*/encryption);
  if (!res.ok()) {
    return res;
  }
  return std::move(context);
}
#else
// Returns a new EVP_CIPHER_CTX for encryption (`encryption` == true) or
// decryption (`encryption` == false) with given `key` and `iv`.
//
// NOTE: Copying the context fails with OpenSSL 3.0, which doesn't provide a
// `dupctx` function for aead ciphers (see [1], [2]).
//
// [1]https://github.com/openssl/openssl/blob/eb52450f5151e8e78743ab05de21a344823316f5/crypto/evp/evp_enc.c#L1427
// [2]https://github.com/openssl/openssl/blob/cac250755efd0c40cc6127a0e4baceb8d226c7e3/providers/implementations/include/prov/ciphercommon_aead.h#L30
absl::StatusOr<internal::SslUniquePtr<EVP_CIPHER_CTX>> NewContext(
    const util::SecretData& key, absl::string_view iv, bool encryption) {
  internal::SslUniquePtr<EVP_CIPHER_CTX> context(EVP_CIPHER_CTX_new());
  if (context == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "EVP_CIPHER_CTX_new failed");
  }
  absl::StatusOr<const EVP_CIPHER*> cipher =
      internal::GetAesGcmCipherForKeySize(key.size());
  if (!cipher.ok()) {
    return cipher.status();
  }
  if (EVP_CipherInit_ex(context.get(), *cipher, /*impl=*/nullptr,
                        reinterpret_cast<const uint8_t*>(key.data()),
                        /*iv=*/nullptr, /*enc=*/1) <= 0) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Context initialization failed");
  }
  absl::Status res =
      SetIvAndDirection(context.get(), iv, /*encryption=*/encryption);
  if (!res.ok()) {
    return res;
  }
  return std::move(context);
}
#endif

// Encrypts/decrypts and removes `bytes_to_crypt` bytes from `input` using
// `context` and writes the result to `writer`. Returns true if the operation
// was successful, false otherwise.
bool DoCryptAndConsume(absl::Cord& input, size_t bytes_to_crypt,
                       EVP_CIPHER_CTX& context, CordWriter& writer) {
  DCHECK(input.size() >= bytes_to_crypt);
  int unused_len = 0;
  while (bytes_to_crypt > 0) {
    // Process at most `kMaxSegmentSize` bytes at a time, then remove the
    // decrypted segment from the Cord.
    const int segment_size = std::min<int>(bytes_to_crypt, kMaxSegmentSize);
    CordReader reader(input);
    int left_in_segment = segment_size;
    while (left_in_segment > 0) {
      absl::string_view chunk = reader.Peek().substr(0, left_in_segment);
      size_t chunk_size = chunk.size();
      while (!chunk.empty()) {
        absl::Span<char> buffer = writer.NextWriteBuffer();
        // Portion of `chunk` to that fits in `buffer`.
        absl::string_view to_crypt = chunk.substr(0, buffer.size());
        if (!EVP_CipherUpdate(
                &context, reinterpret_cast<uint8_t*>(buffer.data()),
                &unused_len,
                reinterpret_cast<const uint8_t*>(to_crypt.data()),
                to_crypt.size())) {
          return false;
        }
        writer.Advance(to_crypt.size());
        chunk.remove_prefix(to_crypt.size());
      }
      left_in_segment -= chunk_size;
      reader.Skip(chunk_size);
    }
    input.RemovePrefix(segment_size);
    bytes_to_crypt -= segment_size;
  }
  return true;
}

}  // namespace

absl::StatusOr<std::unique_ptr<CordAead>> CordAesGcmBoringSsl::New(
    const SecretData& key_value) {
  absl::StatusOr<const EVP_CIPHER*> cipher =
      internal::GetAesGcmCipherForKeySize(key_value.size());
  if (!cipher.ok()) {
    return cipher.status();
  }

  internal::SslUniquePtr<EVP_CIPHER_CTX> partial_context(EVP_CIPHER_CTX_new());
  // Initialize a partial context for the cipher to allow OpenSSL/BoringSSL
  // making some precomputations on the key. Encrypt and Decrypt will try making
  // a copy of this context to avoid doing the same initializations again and to
  // guarantee thread safety.
  //
  // NOTE: It doesn't matter at this point if we set the direction to encryption
  // or decryption, it will be overwritten later any time we call
  // EVP_CipherInit_ex.
  if (EVP_CipherInit_ex(partial_context.get(), *cipher, /*engine=*/nullptr,
                        reinterpret_cast<const uint8_t*>(&key_value[0]),
                        /*iv=*/nullptr, /*enc=*/1) <= 0) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Context initialization failed");
  }

  std::unique_ptr<CordAead> aead = absl::WrapUnique(
      new CordAesGcmBoringSsl(std::move(partial_context), key_value));
  return std::move(aead);
}

absl::StatusOr<absl::Cord> CordAesGcmBoringSsl::Encrypt(
    absl::Cord plaintext, absl::Cord associated_data) const {
  std::string iv = subtle::Random::GetRandomBytes(kIvSizeInBytes);

#if defined(OPENSSL_IS_BORINGSSL) || OPENSSL_VERSION_NUMBER < 0x30000000L
  absl::StatusOr<internal::SslUniquePtr<EVP_CIPHER_CTX>> context =
      NewContextFromPartial(partial_context_.get(), iv, /*encryption=*/true);
#else
  absl::StatusOr<internal::SslUniquePtr<EVP_CIPHER_CTX>> context =
      NewContext(key_, iv, /*encryption=*/true);
#endif
  if (!context.ok()) {
    return context.status();
  }

  int unused_len = 0;
  // Process AAD.
  for (absl::string_view ad_chunk : associated_data.Chunks()) {
    if (!EVP_EncryptUpdate(context->get(), /*out=*/nullptr, &unused_len,
                           reinterpret_cast<const uint8_t*>(ad_chunk.data()),
                           ad_chunk.size())) {
      return absl::Status(absl::StatusCode::kInternal, "Encryption failed");
    }
  }

  CordWriter writer(kIvSizeInBytes + plaintext.size() + kTagSizeInBytes);
  writer.Write(iv);
  if (!DoCryptAndConsume(plaintext, plaintext.size(), **context, writer)) {
    return absl::Status(absl::StatusCode::kInternal, "Encryption failed");
  }

  if (!EVP_EncryptFinal_ex(context->get(), /*out=*/nullptr, &unused_len)) {
    return absl::Status(absl::StatusCode::kInternal, "Encryption failed");
  }

  char tag[kTagSizeInBytes];
  if (!EVP_CIPHER_CTX_ctrl(context->get(), EVP_CTRL_GCM_GET_TAG,
                           kTagSizeInBytes, reinterpret_cast<uint8_t*>(tag))) {
    return absl::Status(absl::StatusCode::kInternal, "Encryption failed");
  }
  writer.Write(absl::string_view(tag, kTagSizeInBytes));
  return std::move(writer).data();
}

absl::StatusOr<absl::Cord> CordAesGcmBoringSsl::Decrypt(
    absl::Cord ciphertext, absl::Cord associated_data) const {
  if (ciphertext.size() < kIvSizeInBytes + kTagSizeInBytes) {
    return absl::Status(absl::StatusCode::kInternal, "Ciphertext too short");
  }

  char iv[kIvSizeInBytes];
  CordReader(ciphertext).ReadN(kIvSizeInBytes, iv);
  ciphertext.RemovePrefix(kIvSizeInBytes);
  absl::string_view iv_view(iv, kIvSizeInBytes);
#if defined(OPENSSL_IS_BORINGSSL) || OPENSSL_VERSION_NUMBER < 0x30000000L
  absl::StatusOr<internal::SslUniquePtr<EVP_CIPHER_CTX>> context =
      NewContextFromPartial(partial_context_.get(), iv_view,
                            /*encryption=*/false);
#else
  absl::StatusOr<internal::SslUniquePtr<EVP_CIPHER_CTX>> context =
      NewContext(key_, iv_view, /*encryption=*/false);
#endif
  if (!context.ok()) {
    return context.status();
  }

  int unused_len = 0;
  // Process associated data.
  for (absl::string_view ad_chunk : associated_data.Chunks()) {
    if (!EVP_DecryptUpdate(context->get(), /*out=*/nullptr, &unused_len,
                           reinterpret_cast<const uint8_t*>(ad_chunk.data()),
                           ad_chunk.size())) {
      return absl::Status(absl::StatusCode::kInternal, "Decryption failed");
    }
  }

  size_t ciphertext_size = ciphertext.size() - kTagSizeInBytes;
  CordWriter writer(ciphertext_size);
  if (!DoCryptAndConsume(ciphertext, ciphertext_size, **context, writer)) {
    return absl::Status(absl::StatusCode::kInternal, "Decryption failed");
  }

  // Set expected tag value to last chunk in ciphertext Cord.
  char tag[kTagSizeInBytes];
  CordReader(ciphertext).ReadN(kTagSizeInBytes, tag);

  if (!EVP_CIPHER_CTX_ctrl(context->get(), EVP_CTRL_GCM_SET_TAG,
                           kTagSizeInBytes, tag)) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Could not set authentication tag");
  }
  // Verify authentication tag.
  if (!EVP_DecryptFinal_ex(context->get(), /*out=*/nullptr, &unused_len)) {
    return absl::Status(absl::StatusCode::kInternal, "Authentication failed");
  }
  return std::move(writer).data();
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
