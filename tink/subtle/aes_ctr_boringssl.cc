// Copyright 2017 Google Inc.
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

#include "tink/subtle/aes_ctr_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "tink/internal/aes_util.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/subtle/ind_cpa_cipher.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

using ::crypto::tink::internal::ScopedAssumeRegionCoreDumpSafe;

util::StatusOr<std::unique_ptr<IndCpaCipher>> AesCtrBoringSsl::New(
    util::SecretData key, int iv_size) {
  auto status = internal::CheckFipsCompatibility<AesCtrBoringSsl>();
  if (!status.ok()) return status;

  util::StatusOr<const EVP_CIPHER*> cipher =
      internal::GetAesCtrCipherForKeySize(key.size());
  if (!cipher.ok()) {
    return cipher.status();
  }

  if (iv_size < kMinIvSizeInBytes || iv_size > kBlockSize) {
    return util::Status(absl::StatusCode::kInvalidArgument, "invalid iv size");
  }
  return {
      absl::WrapUnique(new AesCtrBoringSsl(std::move(key), iv_size, *cipher))};
}

util::StatusOr<std::string> AesCtrBoringSsl::Encrypt(
    absl::string_view plaintext) const {
  // BoringSSL expects a non-null pointer for plaintext, regardless of whether
  // the size is 0.
  plaintext = internal::EnsureStringNonNull(plaintext);

  internal::SslUniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "could not initialize EVP_CIPHER_CTX");
  }
  std::string ciphertext = Random::GetRandomBytes(iv_size_);
  // OpenSSL expects that the IV must be a full block. We pad with zeros.
  std::string iv_block = ciphertext;
  // Note that kBlockSize >= iv_size_ is checked in the factory method.
  // We explicitly add the '\0' argument to stress that we need to initialize
  // the new memory.
  iv_block.resize(kBlockSize, '\0');
  ResizeStringUninitialized(&ciphertext, iv_size_ + plaintext.size());
  // The ciphertext will be fine to leak. This assumes that BoringSSL does not
  // use the memory as scratch pad and writes sensitive data into it.
  ScopedAssumeRegionCoreDumpSafe scope_object(&ciphertext[iv_size_],
                                              plaintext.size());

  util::Status encrypt_result =
      internal::CallWithCoreDumpProtection([&]() -> util::Status {
        int ret = EVP_EncryptInit_ex(
            ctx.get(), cipher_, nullptr /* engine */, key_.data(),
            reinterpret_cast<const uint8_t*>(&iv_block[0]));
        if (ret != 1) {
          return util::Status(absl::StatusCode::kInternal,
                              "could not initialize ctx");
        }
        int len;
        ret = EVP_EncryptUpdate(
            ctx.get(), reinterpret_cast<uint8_t*>(&ciphertext[iv_size_]), &len,
            reinterpret_cast<const uint8_t*>(plaintext.data()),
            plaintext.size());
        if (ret != 1) {
          return util::Status(absl::StatusCode::kInternal, "encryption failed");
        }
        if (len != plaintext.size()) {
          return util::Status(absl::StatusCode::kInternal,
                              "incorrect ciphertext size");
        }
        return util::OkStatus();
      });
  if (!encrypt_result.ok()) {
    return encrypt_result;
  }
  // Declassify the ciphertext: it can depend on the key, but that's
  // intentional.
  crypto::tink::internal::DfsanClearLabel(&ciphertext[iv_size_],
                                          plaintext.size());
  return ciphertext;
}

util::StatusOr<std::string> AesCtrBoringSsl::Decrypt(
    absl::string_view ciphertext) const {
  if (ciphertext.size() < iv_size_) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext too short");
  }

  internal::SslUniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "could not initialize EVP_CIPHER_CTX");
  }

  // Initialise key and IV
  std::string iv_block = std::string(ciphertext.substr(0, iv_size_));
  iv_block.resize(kBlockSize, '\0');

  size_t plaintext_size = ciphertext.size() - iv_size_;
  std::string plaintext;
  ResizeStringUninitialized(&plaintext, plaintext_size);
  // The following implies that the plaintext region is allowed to leak. In
  // successful decryptions, the adversary can already get the plaintext via
  // core dumps (since the API specifies that the plaintext is in a
  // std::string, so this is the users responsibility). Hence, this gives
  // adversaries access to data which is stored *during* the computation, and
  // data which would be erased because the tag is wrong. Since CTR mode uses
  // a key stream which depends only on IV and key, this means the adversary
  // can get the key streams in cases where he couldn't before: for example
  // for keys with a fixed, but unused IV (which seems useless if he didn't see
  // a valid ciphertext) or without querying the actual ciphertext (which does
  // not seem useful), or for very long key streams (longer than for the
  // existing ciphertext, which seems no problem). Hence, we declare this to be
  // sufficiently safe at the moment.
  ScopedAssumeRegionCoreDumpSafe scope_object(plaintext.data(),
                                              plaintext.size());
  util::Status result =
      internal::CallWithCoreDumpProtection([&]() -> util::Status {
        int ret =
            EVP_DecryptInit_ex(ctx.get(), cipher_, nullptr /* engine */,
                               reinterpret_cast<const uint8_t*>(key_.data()),
                               reinterpret_cast<const uint8_t*>(&iv_block[0]));
        if (ret != 1) {
          return util::Status(absl::StatusCode::kInternal,
                              "could not initialize key or iv");
        }

        size_t read = iv_size_;
        int len;
        ret = EVP_DecryptUpdate(
            ctx.get(), reinterpret_cast<uint8_t*>(&plaintext[0]), &len,
            reinterpret_cast<const uint8_t*>(&ciphertext.data()[read]),
            plaintext_size);
        if (ret != 1) {
          return util::Status(absl::StatusCode::kInternal, "decryption failed");
        }

        if (len != plaintext_size) {
          return util::Status(absl::StatusCode::kInternal,
                              "incorrect plaintext size");
        }
        return util::OkStatus();
      });
  if (!result.ok()) {
    return result;
  }
  // The plaintext is declassified due to the API allowing it to leak.
  crypto::tink::internal::DfsanClearLabel(plaintext.data(), plaintext.size());
  return plaintext;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
