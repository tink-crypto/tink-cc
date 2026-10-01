// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/aead/internal/zero_copy_aes_gcm_siv_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead/internal/wycheproof_aead.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/ssl_util.h"
#include "tink/secret_data.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

constexpr int kNonceSizeInBytes = 12;
constexpr int kTagSizeInBytes = 16;

constexpr absl::string_view kKey256Hex =
    "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kMessage = "Some data to encrypt.";
constexpr absl::string_view kAssociatedData = "Some data to authenticate.";

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::AnyOf;
using ::testing::Eq;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

class ZeroCopyAesGcmSivBoringSslTest : public testing::Test {
 protected:
  void SetUp() override {
    SecretData key =
        util::SecretDataFromStringView(test::HexDecodeOrDie(kKey256Hex));
    if (!IsBoringSsl()) {
      ASSERT_THAT(ZeroCopyAesGcmSivBoringSsl::New(key).status(),
                  StatusIs(absl::StatusCode::kUnimplemented));
      GTEST_SKIP() << "Unimplemented with OpenSSL";
    }
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Not supported in FIPS-only mode";
    }

    absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
        ZeroCopyAesGcmSivBoringSsl::New(key);
    ASSERT_THAT(cipher, IsOk());
    cipher_ = std::move(*cipher);
  }

  std::unique_ptr<ZeroCopyAead> cipher_;
};

TEST_F(ZeroCopyAesGcmSivBoringSslTest,
       MaxDecryptionSizeOfMaxEncryptionSizeOfMessageIsMessageSize) {
  EXPECT_EQ(kMessage.size(), cipher_->MaxDecryptionSize(
                                 cipher_->MaxEncryptionSize(kMessage.size())));
}

TEST_F(ZeroCopyAesGcmSivBoringSslTest, EncryptDecrypt) {
  std::string ciphertext;
  subtle::ResizeStringUninitialized(
      &ciphertext, cipher_->MaxEncryptionSize(kMessage.size()));
  absl::StatusOr<int64_t> ciphertext_size =
      cipher_->Encrypt(kMessage, kAssociatedData, absl::MakeSpan(ciphertext));
  ASSERT_THAT(ciphertext_size, IsOk());
  EXPECT_EQ(*ciphertext_size,
            kNonceSizeInBytes + kMessage.size() + kTagSizeInBytes);
  std::string decrypted;
  subtle::ResizeStringUninitialized(
      &decrypted, cipher_->MaxDecryptionSize(ciphertext.size()));
  absl::StatusOr<int64_t> plaintext_size =
      cipher_->Decrypt(ciphertext, kAssociatedData, absl::MakeSpan(decrypted));
  ASSERT_THAT(plaintext_size, IsOk());
  EXPECT_EQ(*plaintext_size, kMessage.size());
  EXPECT_EQ(decrypted, kMessage);
}

TEST_F(ZeroCopyAesGcmSivBoringSslTest, EncryptBufferTooSmall) {
  const int64_t kMaxEncryptionSize =
      kMessage.size() + kNonceSizeInBytes + kTagSizeInBytes;
  std::string ciphertext;
  subtle::ResizeStringUninitialized(&ciphertext, kMaxEncryptionSize - 1);
  EXPECT_THAT(
      cipher_->Encrypt(kMessage, kAssociatedData, absl::MakeSpan(ciphertext))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ZeroCopyAesGcmSivBoringSslTest, DecryptBufferTooSmall) {
  std::string ciphertext;
  subtle::ResizeStringUninitialized(
      &ciphertext, cipher_->MaxEncryptionSize(kMessage.size()));
  ASSERT_THAT(
      cipher_->Encrypt(kMessage, kAssociatedData, absl::MakeSpan(ciphertext)),
      IsOk());

  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext, kMessage.size() - 1);
  EXPECT_THAT(
      cipher_->Decrypt(ciphertext, kAssociatedData, absl::MakeSpan(plaintext))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ZeroCopyAesGcmSivBoringSslTest, DecryptFailsIfCiphertextTooSmall) {
  for (int i = 1; i < kNonceSizeInBytes + kTagSizeInBytes; i++) {
    std::string ciphertext;
    subtle::ResizeStringUninitialized(&ciphertext, i);
    std::string plaintext;
    EXPECT_THAT(
        cipher_->Decrypt(ciphertext, kAssociatedData, absl::MakeSpan(plaintext))
            .status(),
        StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(ZeroCopyAesGcmSivBoringSslStandaloneTest, TestFipsOnly) {
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "Unimplemented with OpenSSL";
  }
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  SecretData key128 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  SecretData key256 = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));

  EXPECT_THAT(ZeroCopyAesGcmSivBoringSsl::New(key128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(ZeroCopyAesGcmSivBoringSsl::New(key256).status(),
              StatusIs(absl::StatusCode::kInternal));
}

class ZeroCopyAesGcmSivBoringSslWycheproofTest
    : public TestWithParam<WycheproofTestVector> {
  void SetUp() override {
    if (!IsBoringSsl()) {
      GTEST_SKIP() << "Unimplemented with OpenSSL";
    }
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Not supported in FIPS-only mode";
    }
    WycheproofTestVector test_vector = GetParam();
    if ((test_vector.key.size() != 16 && test_vector.key.size() != 32) ||
        test_vector.nonce.size() != kNonceSizeInBytes ||
        test_vector.tag.size() != kTagSizeInBytes) {
      GTEST_SKIP() << "Unsupported parameters: key size "
                   << test_vector.key.size()
                   << " nonce size: " << test_vector.nonce.size()
                   << " tag size: " << test_vector.tag.size();
    }
  }
};

TEST_P(ZeroCopyAesGcmSivBoringSslWycheproofTest, Decrypt) {
  WycheproofTestVector test_vector = GetParam();
  SecretData key = util::SecretDataFromStringView(test_vector.key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ZeroCopyAesGcmSivBoringSsl::New(key);
  ASSERT_THAT(cipher, IsOk());
  std::string ciphertext =
      absl::StrCat(test_vector.nonce, test_vector.ct, test_vector.tag);
  std::string plaintext;
  subtle::ResizeStringUninitialized(
      &plaintext, (*cipher)->MaxDecryptionSize(ciphertext.size()));
  absl::StatusOr<int64_t> written_bytes = (*cipher)->Decrypt(
      ciphertext, test_vector.aad, absl::MakeSpan(plaintext));
  if (written_bytes.ok()) {
    EXPECT_NE(test_vector.expected, "invalid");
    EXPECT_EQ(plaintext, test_vector.msg);
  } else {
    EXPECT_THAT(test_vector.expected, Not(AnyOf(Eq("valid"), Eq("acceptable"))))
        << "Could not decrypt test with tcId: " << test_vector.id
        << " iv_size: " << test_vector.nonce.size()
        << " tag_size: " << test_vector.tag.size()
        << " key_size: " << key.size() << "; error: " << written_bytes.status();
  }
}

INSTANTIATE_TEST_SUITE_P(ZeroCopyAesGcmSivBoringSslWycheproofTests,
                         ZeroCopyAesGcmSivBoringSslWycheproofTest,
                         ValuesIn(ReadWycheproofTestVectors(
                             /*file_name=*/"aes_gcm_siv_test.json")));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
