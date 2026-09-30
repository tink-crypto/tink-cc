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

#include "tink/aead/internal/zero_copy_xchacha20_poly1305_boringssl.h"

#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
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

constexpr int kNonceSizeInBytes = 24;
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

class ZeroCopyXChacha20Poly1305BoringSslTest : public testing::Test {
 protected:
  void SetUp() override {
    SecretData key =
        util::SecretDataFromStringView(test::HexDecodeOrDie(kKey256Hex));
    if (!IsBoringSsl()) {
      ASSERT_THAT(ZeroCopyXChacha20Poly1305BoringSsl::New(key).status(),
                  StatusIs(absl::StatusCode::kUnimplemented));
      GTEST_SKIP() << "Unimplemented with OpenSSL";
    }
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Not supported in FIPS-only mode";
    }

    absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
        ZeroCopyXChacha20Poly1305BoringSsl::New(key);
    ASSERT_THAT(cipher, IsOk());
    cipher_ = std::move(*cipher);
  }

  std::unique_ptr<ZeroCopyAead> cipher_;
};

TEST_F(ZeroCopyXChacha20Poly1305BoringSslTest, EncryptDecrypt) {
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

// Test decryption with a known ciphertext, message, associated_data and key
// tuple to make sure this is using the correct algorithm. The values are taken
// from the test vector tcId 1 of the Wycheproof tests:
// https://github.com/google/wycheproof/blob/master/testvectors/xchacha20_poly1305_test.json#L21
TEST_F(ZeroCopyXChacha20Poly1305BoringSslTest, SimpleDecrypt) {
  std::string message = test::HexDecodeOrDie(
      "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66"
      "202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e6520"
      "74697020666f7220746865206675747572652c2073756e73637265656e20776f756c6420"
      "62652069742e");
  std::string raw_ciphertext = test::HexDecodeOrDie(
      "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b"
      "0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945"
      "b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f6"
      "15c68b13b52e");
  std::string iv =
      test::HexDecodeOrDie("404142434445464748494a4b4c4d4e4f5051525354555657");
  std::string tag = test::HexDecodeOrDie("c0875924c1c7987947deafd8780acf49");
  std::string associated_data =
      test::HexDecodeOrDie("50515253c0c1c2c3c4c5c6c7");
  SecretData key = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"));

  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> aead =
      ZeroCopyXChacha20Poly1305BoringSsl::New(key);
  ASSERT_THAT(aead, IsOk());

  std::string ciphertext = absl::StrCat(iv, raw_ciphertext, tag);
  std::string plaintext;
  subtle::ResizeStringUninitialized(
      &plaintext, (*aead)->MaxDecryptionSize(ciphertext.size()));
  absl::StatusOr<int64_t> plaintext_size =
      (*aead)->Decrypt(ciphertext, associated_data, absl::MakeSpan(plaintext));
  ASSERT_THAT(plaintext_size, IsOk());
  EXPECT_EQ(plaintext.substr(0, *plaintext_size), message);
}

TEST_F(ZeroCopyXChacha20Poly1305BoringSslTest,
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

TEST(ZeroCopyXChacha20Poly1305BoringSslStandaloneTest, FailsOnFipsOnlyMode) {
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "Unimplemented with OpenSSL";
  }
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only ran in FIPS-only mode";
  }

  SecretData key256 =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKey256Hex));

  EXPECT_THAT(ZeroCopyXChacha20Poly1305BoringSsl::New(key256).status(),
              StatusIs(absl::StatusCode::kInternal));
}

class ZeroCopyXChacha20Poly1305BoringSslWycheproofTest
    : public TestWithParam<WycheproofTestVector> {
  void SetUp() override {
    if (!IsBoringSsl()) {
      GTEST_SKIP() << "Unimplemented with OpenSSL";
    }
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

TEST_P(ZeroCopyXChacha20Poly1305BoringSslWycheproofTest, Decrypt) {
  WycheproofTestVector test_vector = GetParam();
  SecretData key = util::SecretDataFromStringView(test_vector.key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ZeroCopyXChacha20Poly1305BoringSsl::New(key);
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
        << " key_size: " << key.size() << "; error: " << written_bytes.status();
  }
}

INSTANTIATE_TEST_SUITE_P(ZeroCopyXChacha20Poly1305BoringSslWycheproofTests,
                         ZeroCopyXChacha20Poly1305BoringSslWycheproofTest,
                         ValuesIn(ReadWycheproofTestVectors(
                             /*file_name=*/"xchacha20_poly1305_test.json")));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
