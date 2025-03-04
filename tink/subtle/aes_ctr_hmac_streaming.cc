// Copyright 2019 Google LLC
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

#include "tink/subtle/aes_ctr_hmac_streaming.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "tink/internal/aes_util.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

using ::crypto::tink::internal::CallWithCoreDumpProtection;
using ::crypto::tink::internal::DfsanClearLabel;
using ::crypto::tink::internal::ScopedAssumeRegionCoreDumpSafe;

static std::string NonceForSegment(absl::string_view nonce_prefix,
                                   int64_t segment_number,
                                   bool is_last_segment) {
  return absl::StrCat(
      nonce_prefix, BigEndian32(segment_number),
      is_last_segment ? std::string(1, '\x01') : std::string(1, '\x00'),
      std::string(4, '\x00'));
}

static absl::Status DeriveKeys(const util::SecretData& ikm, HashType hkdf_algo,
                               absl::string_view salt,
                               absl::string_view associated_data, int key_size,
                               util::SecretData* key_value,
                               util::SecretData* hmac_key_value) {
  int derived_key_material_size =
      key_size + AesCtrHmacStreaming::kHmacKeySizeInBytes;
  auto hkdf_result = Hkdf::ComputeHkdf(hkdf_algo, ikm, salt, associated_data,
                                       derived_key_material_size);
  if (!hkdf_result.ok()) return hkdf_result.status();
  util::SecretData key_material = std::move(hkdf_result.value());
  absl::string_view key_material_view =
      util::SecretDataAsStringView(key_material);
  *hmac_key_value =
      util::SecretDataFromStringView(key_material_view.substr(key_size));
  *key_value =
      util::SecretDataFromStringView(key_material_view.substr(0, key_size));
  return absl::OkStatus();
}

static absl::Status Validate(const AesCtrHmacStreaming::Params& params) {
  if (params.ikm.size() < std::max(16, params.key_size)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "input key material too small");
  }
  if (!(params.hkdf_algo == SHA1 || params.hkdf_algo == SHA256 ||
        params.hkdf_algo == SHA512)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "unsupported hkdf_algo");
  }
  if (params.key_size != 16 && params.key_size != 32) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "key_size must be 16 or 32");
  }
  int header_size =
      1 + params.key_size + AesCtrHmacStreaming::kNoncePrefixSizeInBytes;
  if (params.ciphertext_segment_size <=
      params.ciphertext_offset + header_size + params.tag_size) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext_segment_size too small");
  }
  if (params.ciphertext_offset < 0) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext_offset must be non-negative");
  }
  if (params.tag_size < 10) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "tag_size too small");
  }
  if (!(params.tag_algo == SHA1 || params.tag_algo == SHA256 ||
        params.tag_algo == SHA512)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "unsupported tag_algo");
  }
  if ((params.tag_algo == SHA1 && params.tag_size > 20) ||
      (params.tag_algo == SHA256 && params.tag_size > 32) ||
      (params.tag_algo == SHA512 && params.tag_size > 64)) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "tag_size too big");
  }

  return absl::OkStatus();
}

// AesCtrHmacStreaming
// static
absl::StatusOr<std::unique_ptr<AesCtrHmacStreaming>> AesCtrHmacStreaming::New(
    Params params) {
  auto status = internal::CheckFipsCompatibility<AesCtrHmacStreaming>();
  if (!status.ok()) return status;

  status = Validate(params);
  if (!status.ok()) return status;
  return {absl::WrapUnique(new AesCtrHmacStreaming(std::move(params)))};
}

// static
absl::StatusOr<std::unique_ptr<StreamSegmentEncrypter>>
AesCtrHmacStreaming::NewSegmentEncrypter(
    absl::string_view associated_data) const {
  return AesCtrHmacStreamSegmentEncrypter::New(params_, associated_data);
}

// static
absl::StatusOr<std::unique_ptr<StreamSegmentDecrypter>>
AesCtrHmacStreaming::NewSegmentDecrypter(
    absl::string_view associated_data) const {
  return AesCtrHmacStreamSegmentDecrypter::New(params_, associated_data);
}

// AesCtrHmacStreamSegmentEncrypter
static std::string MakeHeader(absl::string_view salt,
                              absl::string_view nonce_prefix) {
  uint8_t header_size =
      static_cast<uint8_t>(1 + salt.size() + nonce_prefix.size());
  return absl::StrCat(std::string(1, header_size), salt, nonce_prefix);
}

// static
absl::StatusOr<std::unique_ptr<StreamSegmentEncrypter>>
AesCtrHmacStreamSegmentEncrypter::New(const AesCtrHmacStreaming::Params& params,
                                      absl::string_view associated_data) {
  auto status = Validate(params);
  if (!status.ok()) return status;

  std::string salt = Random::GetRandomBytes(params.key_size);
  std::string nonce_prefix =
      Random::GetRandomBytes(AesCtrHmacStreaming::kNoncePrefixSizeInBytes);
  std::string header = MakeHeader(salt, nonce_prefix);

  util::SecretData key_value;
  util::SecretData hmac_key_value;
  status = DeriveKeys(params.ikm, params.hkdf_algo, salt, associated_data,
                      params.key_size, &key_value, &hmac_key_value);
  if (!status.ok()) return status;

  absl::StatusOr<const EVP_CIPHER*> cipher =
      internal::GetAesCtrCipherForKeySize(params.key_size);
  if (!cipher.ok()) {
    return cipher.status();
  }

  auto hmac_result = HmacBoringSsl::New(params.tag_algo, params.tag_size,
                                        std::move(hmac_key_value));
  if (!hmac_result.ok()) return hmac_result.status();
  auto mac = std::move(hmac_result.value());

  return {absl::WrapUnique(new AesCtrHmacStreamSegmentEncrypter(
      std::move(key_value), header, nonce_prefix,
      params.ciphertext_segment_size, params.ciphertext_offset, params.tag_size,
      *cipher, std::move(mac)))};
}

namespace {

absl::Status EncryptSensitive(const util::SecretData& key,
                              const EVP_CIPHER& cipher, absl::string_view nonce,
                              absl::string_view plaintext,
                              absl::Span<char> ciphertext) {
  internal::SslUniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (ctx == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "could not initialize EVP_CIPHER_CTX");
  }
  if (EVP_EncryptInit_ex(ctx.get(), &cipher, nullptr /* engine */,
                         reinterpret_cast<const uint8_t*>(key.data()),
                         reinterpret_cast<const uint8_t*>(nonce.data())) != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        "could not initialize ctx");
  }

  int out_len;
  const uint8_t* plaintext_data =
      reinterpret_cast<const uint8_t*>(plaintext.data());
  uint8_t* ciphertext_data = reinterpret_cast<uint8_t*>(ciphertext.data());
  if (EVP_EncryptUpdate(ctx.get(), ciphertext_data, &out_len, plaintext_data,
                        plaintext.size()) != 1) {
    return absl::Status(absl::StatusCode::kInternal, "encryption failed");
  }
  if (out_len != plaintext.size()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "incorrect ciphertext size");
  }

  return absl::OkStatus();
}

absl::Status Encrypt(const util::SecretData& key, const EVP_CIPHER& cipher,
                     absl::string_view nonce, absl::string_view plaintext,
                     absl::Span<char> ciphertext) {
  // The ciphertext will be fine to leak. This assumes that BoringSSL does not
  // use the memory as scratch pad and writes sensitive data into it.
  ScopedAssumeRegionCoreDumpSafe scope_object(ciphertext.data(),
                                              ciphertext.size());
  absl::Status status = CallWithCoreDumpProtection([&]() {
    return EncryptSensitive(
        key, cipher, nonce,
        absl::string_view(reinterpret_cast<const char*>(plaintext.data()),
                          plaintext.size()),
        absl::MakeSpan(reinterpret_cast<char*>(ciphertext.data()),
                       ciphertext.size()));
  });
  if (!status.ok()) {
    return status;
  }
  // Declassify the ciphertext: it can depend on the key, but that's
  // intentional.
  DfsanClearLabel(ciphertext.data(), ciphertext.size());
  return absl::OkStatus();
}

}  // namespace

absl::Status AesCtrHmacStreamSegmentEncrypter::EncryptSegment(
    const std::vector<uint8_t>& plaintext, bool is_last_segment,
    std::vector<uint8_t>* ciphertext_buffer) {
  if (plaintext.size() > get_plaintext_segment_size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "plaintext too long");
  }
  if (ciphertext_buffer == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext_buffer must be non-null");
  }
  if (get_segment_number() > std::numeric_limits<uint32_t>::max() ||
      (get_segment_number() == std::numeric_limits<uint32_t>::max() &&
       !is_last_segment)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "too many segments");
  }

  int ct_size = plaintext.size() + tag_size_;
  ciphertext_buffer->resize(ct_size);

  std::string nonce =
      NonceForSegment(nonce_prefix_, segment_number_, is_last_segment);

  // Encrypt.
  if (absl::Status res = Encrypt(
          key_value_, *cipher_, nonce,
          absl::string_view(reinterpret_cast<const char*>(plaintext.data()),
                            plaintext.size()),
          absl::MakeSpan(reinterpret_cast<char*>(ciphertext_buffer->data()),
                         plaintext.size()));
      !res.ok()) {
    return res;
  }

  // Add MAC tag.
  absl::string_view ciphertext_string(
      reinterpret_cast<const char*>(ciphertext_buffer->data()),
      plaintext.size());
  auto tag_result = mac_->ComputeMac(absl::StrCat(nonce, ciphertext_string));
  if (!tag_result.ok()) return tag_result.status();
  std::string tag = tag_result.value();
  memcpy(ciphertext_buffer->data() + plaintext.size(),
         reinterpret_cast<const uint8_t*>(tag.data()), tag_size_);

  IncSegmentNumber();
  return absl::OkStatus();
}

// AesCtrHmacStreamSegmentDecrypter
// static
absl::StatusOr<std::unique_ptr<StreamSegmentDecrypter>>
AesCtrHmacStreamSegmentDecrypter::New(const AesCtrHmacStreaming::Params& params,
                                      absl::string_view associated_data) {
  auto status = Validate(params);
  if (!status.ok()) return status;

  return {absl::WrapUnique(new AesCtrHmacStreamSegmentDecrypter(
      params.ikm, params.hkdf_algo, params.key_size, associated_data,
      params.ciphertext_segment_size, params.ciphertext_offset, params.tag_algo,
      params.tag_size))};
}

absl::Status AesCtrHmacStreamSegmentDecrypter::Init(
    const std::vector<uint8_t>& header) {
  if (is_initialized_) {
    return absl::Status(absl::StatusCode::kFailedPrecondition,
                        "decrypter alreday initialized");
  }
  if (header.size() != get_header_size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("wrong header size, expected ",
                                     get_header_size(), " bytes"));
  }
  if (header[0] != header.size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "corrupted header");
  }

  // Extract salt and nonce prefix.
  std::string salt(reinterpret_cast<const char*>(header.data() + 1), key_size_);
  nonce_prefix_ =
      std::string(reinterpret_cast<const char*>(header.data() + 1 + key_size_),
                  AesCtrHmacStreaming::kNoncePrefixSizeInBytes);

  util::SecretData hmac_key_value;
  auto status = DeriveKeys(ikm_, hkdf_algo_, salt, associated_data_, key_size_,
                           &key_value_, &hmac_key_value);
  if (!status.ok()) return status;

  absl::StatusOr<const EVP_CIPHER*> cipher =
      internal::GetAesCtrCipherForKeySize(key_size_);
  if (!cipher.ok()) {
    return cipher.status();
  }

  cipher_ = *cipher;

  auto hmac_result =
      HmacBoringSsl::New(tag_algo_, tag_size_, std::move(hmac_key_value));
  if (!hmac_result.ok()) return hmac_result.status();
  mac_ = std::move(hmac_result.value());

  is_initialized_ = true;
  return absl::OkStatus();
}

namespace {

absl::Status DecryptSensitive(const util::SecretData& key,
                              const EVP_CIPHER& cipher, absl::string_view nonce,
                              absl::string_view ciphertext,
                              absl::Span<char> plaintext) {
  // Decrypt.
  internal::SslUniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "could not initialize EVP_CIPHER_CTX");
  }
  if (EVP_DecryptInit_ex(ctx.get(), &cipher, nullptr /* engine */,
                         reinterpret_cast<const uint8_t*>(key.data()),
                         reinterpret_cast<const uint8_t*>(nonce.data())) != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        "could not initialize ctx");
  }
  int out_len;
  const uint8_t* ciphertext_data =
      reinterpret_cast<const uint8_t*>(ciphertext.data());
  uint8_t* plaintext_data = reinterpret_cast<uint8_t*>(plaintext.data());
  if (EVP_DecryptUpdate(ctx.get(), plaintext_data, &out_len, ciphertext_data,
                        ciphertext.size()) != 1) {
    return absl::Status(absl::StatusCode::kInternal, "decryption failed");
  }
  if (out_len != plaintext.size()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "incorrect plaintext size");
  }
  return absl::OkStatus();
}

}  // namespace

absl::Status AesCtrHmacStreamSegmentDecrypter::DecryptSegment(
    const std::vector<uint8_t>& ciphertext, int64_t segment_number,
    bool is_last_segment, std::vector<uint8_t>* plaintext_buffer) {
  if (!is_initialized_) {
    return absl::Status(absl::StatusCode::kFailedPrecondition,
                        "decrypter not initialized");
  }
  if (ciphertext.size() > get_ciphertext_segment_size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext too long");
  }
  if (ciphertext.size() < tag_size_) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext too short");
  }
  if (plaintext_buffer == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "plaintext_buffer must be non-null");
  }
  if (segment_number > std::numeric_limits<uint32_t>::max() ||
      (segment_number == std::numeric_limits<uint32_t>::max() &&
       !is_last_segment)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "too many segments");
  }

  int pt_size = ciphertext.size() - tag_size_;
  plaintext_buffer->resize(pt_size);

  std::string nonce =
      NonceForSegment(nonce_prefix_, segment_number, is_last_segment);

  // Verify MAC tag.
  absl::string_view ciphertext_view(
      reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
  absl::string_view tag = ciphertext_view.substr(pt_size);
  absl::string_view ciphertext_string = ciphertext_view.substr(0, pt_size);
  absl::Status status =
      mac_->VerifyMac(tag, absl::StrCat(nonce, ciphertext_string));
  if (!status.ok()) {
    return status;
  }

  // The following implies that the plaintext region is allowed to leak in core
  // dumps.
  ScopedAssumeRegionCoreDumpSafe scope_object(plaintext_buffer->data(),
                                              plaintext_buffer->size());
  if (absl::Status status = CallWithCoreDumpProtection([&]() {
        return DecryptSensitive(
            key_value_, *cipher_, nonce,
            absl::string_view(reinterpret_cast<const char*>(ciphertext.data()),
                              pt_size),
            absl::MakeSpan(reinterpret_cast<char*>(plaintext_buffer->data()),
                           plaintext_buffer->size()));
      });
      !status.ok()) {
    return status;
  }
  // Declassify the plaintext: it can depend on the key, but that's
  // intentional.
  DfsanClearLabel(plaintext_buffer->data(), plaintext_buffer->size());
  return absl::OkStatus();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
