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

#include "tink/aead/internal/zero_copy_aes_gcm_boringssl.h"

#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/algorithm/container.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/aes_gcm_test_vectors.h"
#include "tink/aead/internal/wycheproof_aead.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Not;
using ::testing::StartsWith;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

constexpr absl::string_view kKey128Hex = "000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kMessage = "Some data to encrypt.";
constexpr absl::string_view kAssociatedData = "Some data to authenticate.";

constexpr int kIvSizeInBytes = 12;
constexpr int kTagSizeInBytes = 16;

constexpr int64_t kMaxDecryptionSize = kMessage.size();

// Encoded ciphertext of kMessage with kAssociatedData and kKey128Hex.
constexpr absl::string_view kEncodedCiphertext =
    "22889553081aa27f0f62ed2f32b068331cb3d8103e121c8b0c898cf70b613e334b7e913323"
    "128429226950dd2f4d42a6fc";

class ZeroCopyAesGcmBoringSslTest : public testing::Test {
 protected:
  void SetUp() override {
    SecretData key =
        util::SecretDataFromStringView(test::HexDecodeOrDie(kKey128Hex));
    absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
        ZeroCopyAesGcmBoringSsl::New(key);
    ASSERT_THAT(cipher, IsOk());
    cipher_ = std::move(*cipher);
  }

  std::unique_ptr<ZeroCopyAead> cipher_;
};

TEST_F(ZeroCopyAesGcmBoringSslTest,
       MaxDecryptionSizeOfMaxEncryptionSizeOfMessageIsMessageSize) {
  // Check i == MaxDecryptionSize(MaxEncryptionSize(i)).
  EXPECT_EQ(kMessage.size(), cipher_->MaxDecryptionSize(
                                 cipher_->MaxEncryptionSize(kMessage.size())));
}

TEST_F(ZeroCopyAesGcmBoringSslTest, MaxEncryptionSizeEqualsCiphertextSize) {
  EXPECT_EQ(cipher_->MaxEncryptionSize(kMessage.size()),
            test::HexDecodeOrDie(kEncodedCiphertext).size());
}

TEST_F(ZeroCopyAesGcmBoringSslTest, MaxDecryptionSizeEqualsPlaintextSize) {
  EXPECT_EQ(cipher_->MaxDecryptionSize(
                test::HexDecodeOrDie(kEncodedCiphertext).size()),
            kMessage.size());
}

TEST_F(ZeroCopyAesGcmBoringSslTest, EncryptDecrypt) {
  std::string ciphertext;
  subtle::ResizeStringUninitialized(
      &ciphertext, cipher_->MaxEncryptionSize(kMessage.size()));
  absl::StatusOr<int64_t> ciphertext_size =
      cipher_->Encrypt(kMessage, kAssociatedData, absl::MakeSpan(ciphertext));
  ASSERT_THAT(ciphertext_size, IsOk());
  EXPECT_EQ(*ciphertext_size,
            kIvSizeInBytes + kMessage.size() + kTagSizeInBytes);
  std::string plaintext;
  subtle::ResizeStringUninitialized(
      &plaintext, cipher_->MaxDecryptionSize(ciphertext.size()));
  absl::StatusOr<int64_t> plaintext_size =
      cipher_->Decrypt(ciphertext, kAssociatedData, absl::MakeSpan(plaintext));

  ASSERT_THAT(plaintext_size, IsOk());
  EXPECT_EQ(plaintext, kMessage);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, DecryptEncodedCiphertext) {
  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext, kMaxDecryptionSize);
  absl::StatusOr<int64_t> plaintext_size =
      cipher_->Decrypt(test::HexDecodeOrDie(kEncodedCiphertext),
                       kAssociatedData, absl::MakeSpan(plaintext));
  ASSERT_THAT(plaintext_size, IsOk());
  EXPECT_EQ(plaintext.substr(0, *plaintext_size), kMessage);
}

TEST_F(ZeroCopyAesGcmBoringSslTest, EncryptBufferTooSmall) {
  const int64_t kMaxEncryptionSize =
      kMessage.size() + kIvSizeInBytes + kTagSizeInBytes;
  std::string ciphertext;
  subtle::ResizeStringUninitialized(&ciphertext, kMaxEncryptionSize - 1);
  EXPECT_THAT(
      cipher_->Encrypt(kMessage, kAssociatedData, absl::MakeSpan(ciphertext))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ZeroCopyAesGcmBoringSslTest, DecryptBufferTooSmall) {
  const int64_t kMaxDecryptionSize = kMessage.size();
  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext, kMaxDecryptionSize - 1);
  EXPECT_THAT(cipher_
                  ->Decrypt(test::HexDecodeOrDie(kEncodedCiphertext),
                            kAssociatedData, absl::MakeSpan(plaintext))
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ZeroCopyAesGcmBoringSslTest, EncryptOverlappingPlaintextCiphertext) {
  std::string buffer(1024, '\0');
  // Copy the kMessage at the beginning of the buffer.
  absl::c_copy(kMessage, std::back_inserter(buffer));
  auto plaintext = absl::string_view(buffer).substr(0, kMessage.size());
  // The output buffer overlaps with a portion of the plaintext, in particular
  // the last kIvSizeInBytes bytes.
  auto cipher_buff =
      absl::MakeSpan(buffer).subspan(kMessage.size() - kIvSizeInBytes);
  EXPECT_THAT(
      cipher_->Encrypt(plaintext, kAssociatedData, cipher_buff).status(),
      StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(ZeroCopyAesGcmBoringSslTest, DecryptOverlappingPlaintextCiphertext) {
  std::string buffer(1024, '\0');
  // Plaintext's buffer starts at the beginning of the buffer.
  auto out_buffer = absl::MakeSpan(buffer).subspan(0, kMessage.size());
  std::string ciphertext_data = test::HexDecodeOrDie(kEncodedCiphertext);
  // Copy the ciphertext into buffer such that the IV part will overlap with the
  // end of the plaintext output buffer.
  int ciphertext_start = kMessage.size() - kIvSizeInBytes;
  memcpy(&buffer[0] + ciphertext_start, ciphertext_data.data(),
         ciphertext_data.size());
  auto ciphertext = absl::string_view(buffer).substr(ciphertext_start,
                                                     ciphertext_data.size());
  EXPECT_THAT(
      cipher_->Decrypt(ciphertext, kAssociatedData, out_buffer).status(),
      StatusIs(absl::StatusCode::kFailedPrecondition));
}

class ZeroCopyAesGcmBoringSslWycheproofTest
    : public TestWithParam<WycheproofTestVector> {
  void SetUp() override {
    WycheproofTestVector test_vector = GetParam();
    if ((test_vector.key.size() != 16 && test_vector.key.size() != 32) ||
        test_vector.nonce.size() != 12 || test_vector.tag.size() != 16) {
      GTEST_SKIP() << "Unsupported parameters: key size "
                   << test_vector.key.size()
                   << " nonce size: " << test_vector.nonce.size()
                   << " tag size: " << test_vector.tag.size();
    }
  }
};

TEST_P(ZeroCopyAesGcmBoringSslWycheproofTest, Decrypt) {
  WycheproofTestVector test_vector = GetParam();
  SecretData key = util::SecretDataFromStringView(test_vector.key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ZeroCopyAesGcmBoringSsl::New(key);
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
    EXPECT_THAT(test_vector.expected, Not(AllOf(Eq("valid"), Eq("acceptable"))))
        << "Could not decrypt test with tcId: " << test_vector.id
        << " iv_size: " << test_vector.nonce.size()
        << " tag_size: " << test_vector.tag.size()
        << " key_size: " << key.size() << "; error: " << written_bytes.status();
  }
}

INSTANTIATE_TEST_SUITE_P(ZeroCopyAesGcmBoringSslWycheproofTests,
                         ZeroCopyAesGcmBoringSslWycheproofTest,
                         ValuesIn(ReadWycheproofTestVectors(
                             /*file_name=*/"aes_gcm_test.json")));

using ZeroCopyAesGcmBoringSslTestVectorTest = TestWithParam<AeadTestVector>;

TEST_P(ZeroCopyAesGcmBoringSslTestVectorTest, Decrypt) {
  const AeadTestVector& test_vector = GetParam();
  const AesGcmKey& key = dynamic_cast<const AesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ZeroCopyAesGcmBoringSsl::New(key);
  ASSERT_THAT(cipher, IsOk());
  std::string plaintext;
  subtle::ResizeStringUninitialized(
      &plaintext, (*cipher)->MaxDecryptionSize(test_vector.ciphertext.size()));
  absl::StatusOr<int64_t> plaintext_size =
      (*cipher)->Decrypt(test_vector.ciphertext, test_vector.associated_data,
                         absl::MakeSpan(plaintext));
  ASSERT_THAT(plaintext_size, IsOk());
  plaintext.resize(*plaintext_size);
  EXPECT_EQ(plaintext, test_vector.plaintext);
}

TEST_P(ZeroCopyAesGcmBoringSslTestVectorTest, EncryptDecrypt) {
  const AeadTestVector& test_vector = GetParam();
  const AesGcmKey& key = dynamic_cast<const AesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ZeroCopyAesGcmBoringSsl::New(key);
  ASSERT_THAT(cipher, IsOk());
  std::string ciphertext;
  subtle::ResizeStringUninitialized(
      &ciphertext, (*cipher)->MaxEncryptionSize(test_vector.plaintext.size()));
  absl::StatusOr<int64_t> ciphertext_size =
      (*cipher)->Encrypt(test_vector.plaintext, test_vector.associated_data,
                         absl::MakeSpan(ciphertext));
  ASSERT_THAT(ciphertext_size, IsOk());
  ciphertext.resize(*ciphertext_size);
  if (!key.GetOutputPrefix().empty()) {
    EXPECT_THAT(ciphertext, StartsWith(key.GetOutputPrefix()));
  }
  std::string plaintext;
  subtle::ResizeStringUninitialized(
      &plaintext, (*cipher)->MaxDecryptionSize(ciphertext.size()));
  absl::StatusOr<int64_t> plaintext_size = (*cipher)->Decrypt(
      ciphertext, test_vector.associated_data, absl::MakeSpan(plaintext));
  ASSERT_THAT(plaintext_size, IsOk());
  plaintext.resize(*plaintext_size);
  EXPECT_EQ(plaintext, test_vector.plaintext);
}

TEST_P(ZeroCopyAesGcmBoringSslTestVectorTest,
       MaxEncryptionSizeEqualsCiphertextSize) {
  const AeadTestVector& test_vector = GetParam();
  const AesGcmKey& key = dynamic_cast<const AesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ZeroCopyAesGcmBoringSsl::New(key);
  ASSERT_THAT(cipher, IsOk());
  EXPECT_EQ((*cipher)->MaxEncryptionSize(test_vector.plaintext.size()),
            test_vector.ciphertext.size());
}

TEST_P(ZeroCopyAesGcmBoringSslTestVectorTest,
       MaxDecryptionSizeEqualsPlaintextSize) {
  const AeadTestVector& test_vector = GetParam();
  const AesGcmKey& key = dynamic_cast<const AesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ZeroCopyAesGcmBoringSsl::New(key);
  ASSERT_THAT(cipher, IsOk());
  EXPECT_EQ((*cipher)->MaxDecryptionSize(test_vector.ciphertext.size()),
            test_vector.plaintext.size());
}

INSTANTIATE_TEST_SUITE_P(ZeroCopyAesGcmBoringSslTestVectorTests,
                         ZeroCopyAesGcmBoringSslTestVectorTest,
                         ValuesIn(CreateAesGcmTestVectors()));

TEST(ZeroCopyAesGcmBoringSslKeyTest, InvalidIvSizeFails) {
  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<AesGcmKey> key =
      AesGcmKey::Create(*parameters,
                        RestrictedData(test::HexDecodeOrDie(kKey128Hex),
                                       InsecureSecretKeyAccess::Get()),
                        /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(ZeroCopyAesGcmBoringSsl::New(*key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ZeroCopyAesGcmBoringSslKeyTest, InvalidTagSizeFails) {
  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(12)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<AesGcmKey> key =
      AesGcmKey::Create(*parameters,
                        RestrictedData(test::HexDecodeOrDie(kKey128Hex),
                                       InsecureSecretKeyAccess::Get()),
                        /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(ZeroCopyAesGcmBoringSsl::New(*key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ZeroCopyAesGcmBoringSslKeyTest, InvalidKeySizeFails) {
  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(24)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *parameters,
      RestrictedData(std::string(24, 'a'), InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(ZeroCopyAesGcmBoringSsl::New(*key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ZeroCopyAesGcmBoringSslKeyTest, DecryptWithBadPrefixFails) {
  const AeadTestVector& test_vector =
      GetAesGcmTestVector(16, AesGcmParameters::Variant::kTink);
  const AesGcmKey& key = dynamic_cast<const AesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ZeroCopyAesGcmBoringSsl::New(key);
  ASSERT_THAT(cipher, IsOk());

  std::string bad_ciphertext = test_vector.ciphertext;
  bad_ciphertext[0] ^= 0x01;  // Corrupt prefix

  std::string plaintext;
  subtle::ResizeStringUninitialized(
      &plaintext, (*cipher)->MaxDecryptionSize(bad_ciphertext.size()));
  EXPECT_THAT((*cipher)
                  ->Decrypt(bad_ciphertext, test_vector.associated_data,
                            absl::MakeSpan(plaintext))
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
