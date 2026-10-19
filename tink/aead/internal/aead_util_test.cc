// Copyright 2021 Google LLC
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
#include "tink/aead/internal/aead_util.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "openssl/evp.h"

#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/aead.h"
#include "openssl/cipher.h"
#include "openssl/nid.h"
#endif

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::AllOf;
using ::testing::Not;
using ::testing::ResultOf;

TEST(AeadUtilTest, GetAesGcmCipherForKeySize) {
  for (int i = 0; i < 64; i++) {
    absl::StatusOr<const EVP_CIPHER *> cipher = GetAesGcmCipherForKeySize(i);
    if (i == 16) {
      EXPECT_THAT(cipher,
                  IsOkAndHolds(ResultOf(EVP_CIPHER_nid, NID_aes_128_gcm)));
    } else if (i == 32) {
      EXPECT_THAT(cipher,
                  IsOkAndHolds(ResultOf(EVP_CIPHER_nid, NID_aes_256_gcm)));
    } else {
      EXPECT_THAT(cipher, Not(IsOk()));
    }
  }
}

TEST(AeadUtilTest, SupportedKmsEnvelopeAeadDekKeyTypes) {
  EXPECT_THAT(IsSupportedKmsEnvelopeAeadDekKeyType(
                  "type.googleapis.com/google.crypto.tink.AesGcmKey"),
              IsTrue());
  EXPECT_THAT(IsSupportedKmsEnvelopeAeadDekKeyType(
                  "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey"),
              IsFalse());
}

#ifdef OPENSSL_IS_BORINGSSL

absl::StatusOr<bool> CiphertextDependsOnAdditionalData(const EVP_AEAD* cipher) {
  const std::string kKey(EVP_AEAD_key_length(cipher), 'K');
  const std::string kNonce(EVP_AEAD_nonce_length(cipher), 'N');
  const std::string kPlaintext = "hello";
  const std::string kAad1 = "one";
  const std::string kAad2 = "two";

  bssl::ScopedEVP_AEAD_CTX ctx;
  if (!EVP_AEAD_CTX_init(ctx.get(), cipher,
                         reinterpret_cast<const uint8_t*>(kKey.data()),
                         kKey.size(), EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr)) {
    return absl::InternalError("Failed to initialize EVP_AEAD_CTX");
  }

  std::string ciphertext1(kPlaintext.size(), '1');
  std::string ciphertext2(kPlaintext.size(), '2');
  std::string tag(EVP_AEAD_max_overhead(cipher), 'T');
  size_t tag_len;

  if (!EVP_AEAD_CTX_seal_scatter(
          ctx.get(), reinterpret_cast<uint8_t*>(ciphertext1.data()),
          reinterpret_cast<uint8_t*>(tag.data()), &tag_len, tag.size(),
          reinterpret_cast<const uint8_t*>(kNonce.data()), kNonce.size(),
          reinterpret_cast<const uint8_t*>(kPlaintext.data()),
          kPlaintext.size(), nullptr, 0,
          reinterpret_cast<const uint8_t*>(kAad1.data()), kAad1.size())) {
    return absl::InternalError("Failed to seal ciphertext1");
  }
  if (!EVP_AEAD_CTX_seal_scatter(
          ctx.get(), reinterpret_cast<uint8_t*>(ciphertext2.data()),
          reinterpret_cast<uint8_t*>(tag.data()), &tag_len, tag.size(),
          reinterpret_cast<const uint8_t*>(kNonce.data()), kNonce.size(),
          reinterpret_cast<const uint8_t*>(kPlaintext.data()),
          kPlaintext.size(), nullptr, 0,
          reinterpret_cast<const uint8_t*>(kAad2.data()), kAad2.size())) {
    return absl::InternalError("Failed to seal ciphertext2");
  }

  return (ciphertext1 != ciphertext2);
}

TEST(AeadUtilTest, GetAesAeadForKeySize) {
  for (int i = 0; i < 64; i++) {
    absl::StatusOr<const EVP_AEAD *> cipher = GetAesGcmAeadForKeySize(i);
    if (i == 16 || i == 32) {
      // EVP_AEAD has no NIDs, so, distinguish AES modes by their input sizes
      // and whether they use our nonce as is (AES-GCM) or compute a synthetic
      // IV based on the nonce, plaintext and additional data (AES-GCM-SIV).
      EXPECT_THAT(cipher,
                  IsOkAndHolds(AllOf(ResultOf(EVP_AEAD_key_length, i),
                                     ResultOf(EVP_AEAD_nonce_length, 12),
                                     ResultOf(EVP_AEAD_max_overhead, 16),
                                     ResultOf(EVP_AEAD_max_tag_len, 16),
                                     ResultOf(CiphertextDependsOnAdditionalData,
                                              IsOkAndHolds(IsFalse())))));
    } else {
      EXPECT_THAT(cipher, Not(IsOk()));
    }
  }
}

TEST(AeadUtilTest, GetAesGcmSivAeadCipherForKeySize) {
  for (int i = 0; i < 64; i++) {
    absl::StatusOr<const EVP_AEAD *> cipher =
        GetAesGcmSivAeadCipherForKeySize(i);
    if (i == 16 || i == 32) {
      // EVP_AEAD has no NIDs, so, distinguish AES modes by their input sizes
      // and whether they use our nonce as is (AES-GCM) or compute a synthetic
      // IV based on the nonce, plaintext and additional data (AES-GCM-SIV).
      EXPECT_THAT(cipher,
                  IsOkAndHolds(AllOf(ResultOf(EVP_AEAD_key_length, i),
                                     ResultOf(EVP_AEAD_nonce_length, 12),
                                     ResultOf(EVP_AEAD_max_overhead, 16),
                                     ResultOf(EVP_AEAD_max_tag_len, 16),
                                     ResultOf(CiphertextDependsOnAdditionalData,
                                              IsOkAndHolds(IsTrue())))));
    } else {
      EXPECT_THAT(cipher, Not(IsOk()));
    }
  }
}

#endif

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
