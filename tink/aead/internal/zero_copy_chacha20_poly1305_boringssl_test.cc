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

#include "tink/aead/internal/zero_copy_chacha20_poly1305_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
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
#include "tink/aead/chacha20_poly1305_key.h"
#include "tink/aead/chacha20_poly1305_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/chacha20_poly1305_test_vectors.h"
#include "tink/aead/internal/wycheproof_aead.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/subtle_util.h"
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
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::AnyOf;
using ::testing::Eq;
using ::testing::Not;
using ::testing::StartsWith;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

class ZeroCopyChaCha20Poly1305BoringSslTest : public testing::Test {
 protected:
  void SetUp() override {
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Not supported in FIPS-only mode";
    }

    absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
        ChaCha20Poly1305Parameters::Variant::kNoPrefix,
        RestrictedData(test::HexDecodeOrDie(kKey256Hex),
                       InsecureSecretKeyAccess::Get()),
        /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
    ASSERT_THAT(key, IsOk());

    absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
        ChaCha20Poly1305ZeroCopyAead(*key);
    ASSERT_THAT(cipher, IsOk());
    cipher_ = std::move(*cipher);
  }

  std::unique_ptr<ZeroCopyAead> cipher_;
};

TEST_F(ZeroCopyChaCha20Poly1305BoringSslTest, EncryptDecrypt) {
  std::string ciphertext;
  subtle::ResizeStringUninitialized(
      &ciphertext, cipher_->MaxEncryptionSize(kMessage.size()));
  absl::StatusOr<int64_t> ciphertext_size =
      cipher_->Encrypt(kMessage, kAssociatedData, absl::MakeSpan(ciphertext));
  ASSERT_THAT(ciphertext_size, IsOk());
  ciphertext.resize(*ciphertext_size);
  std::string decrypted;
  subtle::ResizeStringUninitialized(
      &decrypted, cipher_->MaxDecryptionSize(ciphertext.size()));
  absl::StatusOr<int64_t> plaintext_size =
      cipher_->Decrypt(ciphertext, kAssociatedData, absl::MakeSpan(decrypted));
  ASSERT_THAT(plaintext_size, IsOk());
  decrypted.resize(*plaintext_size);
  EXPECT_EQ(decrypted, kMessage);
}

TEST_F(ZeroCopyChaCha20Poly1305BoringSslTest,
       DecryptFailsIfCiphertextTooSmall) {
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

TEST(ZeroCopyChaCha20Poly1305BoringSslStandaloneTest, FailsOnFipsOnlyMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only ran in FIPS-only mode";
  }

  const AeadTestVector& test_vector =
      GetChaCha20Poly1305TestVector(ChaCha20Poly1305Parameters::Variant::kTink);
  const ChaCha20Poly1305Key& tink_key =
      dynamic_cast<const ChaCha20Poly1305Key&>(*test_vector.aead_key);
  EXPECT_THAT(ChaCha20Poly1305ZeroCopyAead(tink_key).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST_F(ZeroCopyChaCha20Poly1305BoringSslTest, EncryptBufferTooSmall) {
  std::string ciphertext;
  subtle::ResizeStringUninitialized(
      &ciphertext, cipher_->MaxEncryptionSize(kMessage.size()) - 1);
  EXPECT_THAT(
      cipher_->Encrypt(kMessage, kAssociatedData, absl::MakeSpan(ciphertext))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ZeroCopyChaCha20Poly1305BoringSslTest, DecryptBufferTooSmall) {
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

TEST_F(ZeroCopyChaCha20Poly1305BoringSslTest,
       EncryptOverlappingPlaintextCiphertext) {
  std::string buffer(1024, '\0');
  absl::c_copy(kMessage, buffer.begin());
  absl::string_view plaintext =
      absl::string_view(buffer).substr(0, kMessage.size());
  absl::Span<char> cipher_buff = absl::MakeSpan(buffer).subspan(1);
  EXPECT_THAT(
      cipher_->Encrypt(plaintext, kAssociatedData, cipher_buff).status(),
      StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(ZeroCopyChaCha20Poly1305BoringSslTest,
       DecryptOverlappingPlaintextCiphertext) {
  std::string ciphertext;
  subtle::ResizeStringUninitialized(
      &ciphertext, cipher_->MaxEncryptionSize(kMessage.size()));
  ASSERT_THAT(
      cipher_->Encrypt(kMessage, kAssociatedData, absl::MakeSpan(ciphertext)),
      IsOk());

  std::string buffer(1024, '\0');
  absl::Span<char> out_buffer =
      absl::MakeSpan(buffer).subspan(0, kMessage.size());
  int ciphertext_start = 1;
  std::memcpy(&buffer[0] + ciphertext_start, ciphertext.data(),
              ciphertext.size());
  absl::string_view overlapping_ct =
      absl::string_view(buffer).substr(ciphertext_start, ciphertext.size());
  EXPECT_THAT(
      cipher_->Decrypt(overlapping_ct, kAssociatedData, out_buffer).status(),
      StatusIs(absl::StatusCode::kFailedPrecondition));
}

class ZeroCopyChaCha20Poly1305BoringSslWycheproofTest
    : public TestWithParam<WycheproofTestVector> {
  void SetUp() override {
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Not supported in FIPS-only mode";
    }
    WycheproofTestVector test_vector = GetParam();
    if (test_vector.key.size() != 32 ||
        test_vector.nonce.size() != kNonceSizeInBytes ||
        test_vector.tag.size() != kTagSizeInBytes) {
      GTEST_SKIP() << "Unsupported parameters: key size "
                   << test_vector.key.size()
                   << " nonce size: " << test_vector.nonce.size()
                   << " tag size: " << test_vector.tag.size();
    }
  }
};

TEST_P(ZeroCopyChaCha20Poly1305BoringSslWycheproofTest, Decrypt) {
  WycheproofTestVector test_vector = GetParam();
  absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      ChaCha20Poly1305Parameters::Variant::kNoPrefix,
      RestrictedData(test_vector.key, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ChaCha20Poly1305ZeroCopyAead(*key);
  ASSERT_THAT(cipher, IsOk());
  std::string ciphertext =
      absl::StrCat(test_vector.nonce, test_vector.ct, test_vector.tag);
  std::string plaintext;
  subtle::ResizeStringUninitialized(
      &plaintext, (*cipher)->MaxDecryptionSize(ciphertext.size()));
  absl::StatusOr<int64_t> written_bytes = (*cipher)->Decrypt(
      ciphertext, test_vector.aad, absl::MakeSpan(plaintext));
  if (written_bytes.ok()) {
    EXPECT_NE(test_vector.expected, "invalid")
        << "Decrypted invalid ciphertext with ID " << test_vector.id;
    EXPECT_EQ(plaintext, test_vector.msg)
        << "Incorrect decryption: " << test_vector.id;
  } else {
    EXPECT_THAT(test_vector.expected, Not(AnyOf(Eq("valid"), Eq("acceptable"))))
        << "Could not decrypt test with tcId: " << test_vector.id
        << " iv_size: " << test_vector.nonce.size()
        << " tag_size: " << test_vector.tag.size()
        << " key_size: " << test_vector.key.size()
        << "; error: " << written_bytes.status();
  }
}

INSTANTIATE_TEST_SUITE_P(ZeroCopyChaCha20Poly1305BoringSslWycheproofTests,
                         ZeroCopyChaCha20Poly1305BoringSslWycheproofTest,
                         ValuesIn(ReadWycheproofTestVectors(
                             /*file_name=*/"chacha20_poly1305_test.json")));

class ZeroCopyChaCha20Poly1305BoringSslTestVectorTest
    : public TestWithParam<AeadTestVector> {
 protected:
  void SetUp() override {
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Not supported in FIPS-only mode";
    }
  }
};

TEST_P(ZeroCopyChaCha20Poly1305BoringSslTestVectorTest, Decrypt) {
  const AeadTestVector& test_vector = GetParam();
  const ChaCha20Poly1305Key& key =
      dynamic_cast<const ChaCha20Poly1305Key&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ChaCha20Poly1305ZeroCopyAead(key);
  ASSERT_THAT(cipher, IsOk());
  std::string plaintext;
  subtle::ResizeStringUninitialized(
      &plaintext, (*cipher)->MaxDecryptionSize(test_vector.ciphertext.size()));
  ASSERT_THAT(
      (*cipher)->Decrypt(test_vector.ciphertext, test_vector.associated_data,
                         absl::MakeSpan(plaintext)),
      IsOkAndHolds(static_cast<int64_t>(test_vector.plaintext.size())));
  EXPECT_EQ(plaintext, test_vector.plaintext);
}

TEST_P(ZeroCopyChaCha20Poly1305BoringSslTestVectorTest, EncryptDecrypt) {
  const AeadTestVector& test_vector = GetParam();
  const ChaCha20Poly1305Key& key =
      dynamic_cast<const ChaCha20Poly1305Key&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ChaCha20Poly1305ZeroCopyAead(key);
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

TEST_P(ZeroCopyChaCha20Poly1305BoringSslTestVectorTest,
       MaxEncryptionSizeEqualsCiphertextSize) {
  const AeadTestVector& test_vector = GetParam();
  const ChaCha20Poly1305Key& key =
      dynamic_cast<const ChaCha20Poly1305Key&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ChaCha20Poly1305ZeroCopyAead(key);
  ASSERT_THAT(cipher, IsOk());
  EXPECT_EQ((*cipher)->MaxEncryptionSize(test_vector.plaintext.size()),
            static_cast<int64_t>(test_vector.ciphertext.size()));
}

TEST_P(ZeroCopyChaCha20Poly1305BoringSslTestVectorTest,
       MaxDecryptionSizeEqualsPlaintextSize) {
  const AeadTestVector& test_vector = GetParam();
  const ChaCha20Poly1305Key& key =
      dynamic_cast<const ChaCha20Poly1305Key&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ChaCha20Poly1305ZeroCopyAead(key);
  ASSERT_THAT(cipher, IsOk());
  EXPECT_EQ((*cipher)->MaxDecryptionSize(test_vector.ciphertext.size()),
            static_cast<int64_t>(test_vector.plaintext.size()));
}

INSTANTIATE_TEST_SUITE_P(ZeroCopyChaCha20Poly1305BoringSslTestVectorTests,
                         ZeroCopyChaCha20Poly1305BoringSslTestVectorTest,
                         ValuesIn(CreateChaCha20Poly1305TestVectors()));

TEST(ZeroCopyChaCha20Poly1305BoringSslKeyTest, DecryptWithBadPrefixFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  const AeadTestVector& test_vector =
      GetChaCha20Poly1305TestVector(ChaCha20Poly1305Parameters::Variant::kTink);
  const ChaCha20Poly1305Key& key =
      dynamic_cast<const ChaCha20Poly1305Key&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ChaCha20Poly1305ZeroCopyAead(key);
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

TEST(ZeroCopyChaCha20Poly1305BoringSslKeyTest,
     DecryptWithShortPrefixedCiphertextFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  const AeadTestVector& test_vector =
      GetChaCha20Poly1305TestVector(ChaCha20Poly1305Parameters::Variant::kTink);
  const ChaCha20Poly1305Key& key =
      dynamic_cast<const ChaCha20Poly1305Key&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ChaCha20Poly1305ZeroCopyAead(key);
  ASSERT_THAT(cipher, IsOk());

  const size_t min_size =
      key.GetOutputPrefix().size() + kNonceSizeInBytes + kTagSizeInBytes;
  EXPECT_EQ((*cipher)->MaxDecryptionSize(min_size), 0);
  std::string short_ciphertext(min_size - 1, 'a');
  std::string plaintext;
  EXPECT_THAT((*cipher)
                  ->Decrypt(short_ciphertext, test_vector.associated_data,
                            absl::MakeSpan(plaintext))
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
