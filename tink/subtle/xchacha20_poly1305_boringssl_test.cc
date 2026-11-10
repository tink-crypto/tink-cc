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

#include "tink/subtle/xchacha20_poly1305_boringssl.h"

#include <cstddef>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/xchacha20_poly1305_test_vectors.h"
#include "tink/aead/internal/wycheproof_aead.h"
#include "tink/aead/xchacha20_poly1305_key.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/ssl_util.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

constexpr int kNonceSizeInBytes = 24;
constexpr int kTagSizeInBytes = 16;

constexpr absl::string_view kKey256Hex =
    "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kMessage = "Some data to encrypt.";
constexpr absl::string_view kAssociatedData = "Some data to authenticate.";

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::AeadTestVector;
using ::crypto::tink::internal::CreateXChaCha20Poly1305TestVectors;
using ::crypto::tink::internal::GetXChaCha20Poly1305TestVector;
using ::testing::AnyOf;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::StartsWith;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

TEST(XChacha20Poly1305BoringSslTest, EncryptDecrypt) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  SecretData key =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKey256Hex));
  if (!internal::IsBoringSsl()) {
    EXPECT_THAT(XChacha20Poly1305BoringSsl::New(key).status(),
                StatusIs(absl::StatusCode::kUnimplemented));
  } else {
    absl::StatusOr<std::unique_ptr<Aead>> aead =
        XChacha20Poly1305BoringSsl::New(key);
    ASSERT_THAT(aead, IsOk());

    absl::StatusOr<std::string> ciphertext =
        (*aead)->Encrypt(kMessage, kAssociatedData);
    ASSERT_THAT(ciphertext, IsOk());
    EXPECT_THAT(*ciphertext,
                SizeIs(kMessage.size() + kNonceSizeInBytes + kTagSizeInBytes));
    absl::StatusOr<std::string> plaintext =
        (*aead)->Decrypt(*ciphertext, kAssociatedData);
    ASSERT_THAT(plaintext, IsOk());
    EXPECT_EQ(*plaintext, kMessage);
  }
}

// Test decryption with a known ciphertext, message, associated_data and key
// tuple to make sure this is using the correct algorithm. The values are taken
// from the test vector tcId 1 of the Wycheproof tests:
// https://github.com/google/wycheproof/blob/master/testvectors/xchacha20_poly1305_test.json#L21
TEST(XChacha20Poly1305BoringSslTest, SimpleDecrypt) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "Unimplemented with OpenSSL";
  }
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

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

  absl::StatusOr<std::unique_ptr<Aead>> aead =
      XChacha20Poly1305BoringSsl::New(key);
  ASSERT_THAT(aead, IsOk());

  absl::StatusOr<std::string> plaintext =
      (*aead)->Decrypt(absl::StrCat(iv, raw_ciphertext, tag), associated_data);
  ASSERT_THAT(plaintext, IsOk());
  EXPECT_EQ(*plaintext, message);
}

TEST(XChacha20Poly1305BoringSslTest, DecryptFailsIfCiphertextTooSmall) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "Unimplemented with OpenSSL";
  }
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  SecretData key =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKey256Hex));
  absl::StatusOr<std::unique_ptr<Aead>> aead =
      XChacha20Poly1305BoringSsl::New(key);
  ASSERT_THAT(aead, IsOk());

  for (int i = 1; i < kNonceSizeInBytes + kTagSizeInBytes; i++) {
    std::string ciphertext;
    ResizeStringUninitialized(&ciphertext, i);
    EXPECT_THAT((*aead)->Decrypt(ciphertext, kAssociatedData).status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(XChacha20Poly1305BoringSslTest, FailisOnFipsOnlyMode) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "Unimplemented with OpenSSL";
  }
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only ran in in FIPS-only mode";
  }

  SecretData key256 =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKey256Hex));

  EXPECT_THAT(XChacha20Poly1305BoringSsl::New(key256).status(),
              StatusIs(absl::StatusCode::kInternal));

  const AeadTestVector& test_vector = GetXChaCha20Poly1305TestVector(
      XChaCha20Poly1305Parameters::Variant::kTink);
  EXPECT_THAT(
      XChacha20Poly1305BoringSsl::New(
          dynamic_cast<const XChaCha20Poly1305Key&>(*test_vector.aead_key))
          .status(),
      StatusIs(absl::StatusCode::kInternal));
}

class XChacha20Poly1305BoringSslTestVectorTest
    : public TestWithParam<AeadTestVector> {
 protected:
  void SetUp() override {
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Not supported in FIPS-only mode";
    }
  }
};

TEST_P(XChacha20Poly1305BoringSslTestVectorTest, DecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const XChaCha20Poly1305Key& key =
      dynamic_cast<const XChaCha20Poly1305Key&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead =
      XChacha20Poly1305BoringSsl::New(key);
  ASSERT_THAT(aead, IsOk());

  EXPECT_THAT(
      (*aead)->Decrypt(test_vector.ciphertext, test_vector.associated_data),
      IsOkAndHolds(test_vector.plaintext));
}

TEST_P(XChacha20Poly1305BoringSslTestVectorTest, EncryptDecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const XChaCha20Poly1305Key& key =
      dynamic_cast<const XChaCha20Poly1305Key&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead =
      XChacha20Poly1305BoringSsl::New(key);
  ASSERT_THAT(aead, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(test_vector.plaintext, test_vector.associated_data);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT(*ciphertext, StartsWith(key.GetOutputPrefix()));

  EXPECT_THAT((*aead)->Decrypt(*ciphertext, test_vector.associated_data),
              IsOkAndHolds(test_vector.plaintext));
}

INSTANTIATE_TEST_SUITE_P(XChacha20Poly1305BoringSslTestVectorTests,
                         XChacha20Poly1305BoringSslTestVectorTest,
                         ValuesIn(CreateXChaCha20Poly1305TestVectors()));

TEST(XChacha20Poly1305BoringSslTest,
     DecryptWithKeyFailsWithModifiedCiphertextOrAssociatedData) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  const AeadTestVector& test_vector = GetXChaCha20Poly1305TestVector(
      XChaCha20Poly1305Parameters::Variant::kTink);
  const XChaCha20Poly1305Key& key =
      dynamic_cast<const XChaCha20Poly1305Key&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead =
      XChacha20Poly1305BoringSsl::New(key);
  ASSERT_THAT(aead, IsOk());

  for (size_t i = 0; i < test_vector.ciphertext.size(); ++i) {
    std::string modified_ciphertext = test_vector.ciphertext;
    modified_ciphertext[i] ^= 0x01;
    EXPECT_THAT((*aead)
                    ->Decrypt(modified_ciphertext, test_vector.associated_data)
                    .status(),
                Not(IsOk()));
  }

  EXPECT_THAT((*aead)
                  ->Decrypt(test_vector.ciphertext, "modified associated data")
                  .status(),
              Not(IsOk()));

  for (size_t len = 0; len < test_vector.ciphertext.size(); ++len) {
    EXPECT_THAT(
        (*aead)
            ->Decrypt(absl::string_view(test_vector.ciphertext).substr(0, len),
                      test_vector.associated_data)
            .status(),
        Not(IsOk()));
  }
}

class XChacha20Poly1305BoringSslWycheproofTest
    : public TestWithParam<internal::WycheproofTestVector> {
  void SetUp() override {
    if (!internal::IsBoringSsl()) {
      GTEST_SKIP() << "Unimplemented with OpenSSL";
    }
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Not supported in FIPS-only mode";
    }
    internal::WycheproofTestVector test_vector = GetParam();
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

TEST_P(XChacha20Poly1305BoringSslWycheproofTest, Decrypt) {
  internal::WycheproofTestVector test_vector = GetParam();
  SecretData key = util::SecretDataFromStringView(test_vector.key);
  absl::StatusOr<std::unique_ptr<Aead>> cipher =
      XChacha20Poly1305BoringSsl::New(key);
  ASSERT_THAT(cipher, IsOk());
  std::string ciphertext =
      absl::StrCat(test_vector.nonce, test_vector.ct, test_vector.tag);
  absl::StatusOr<std::string> plaintext =
      (*cipher)->Decrypt(ciphertext, test_vector.aad);
  if (plaintext.ok()) {
    EXPECT_NE(test_vector.expected, "invalid")
        << "Decrypted invalid ciphertext with ID " << test_vector.id;
    EXPECT_EQ(*plaintext, test_vector.msg)
        << "Incorrect decryption: " << test_vector.id;
  } else {
    EXPECT_THAT(test_vector.expected, Not(AnyOf(Eq("valid"), Eq("acceptable"))))
        << "Could not decrypt test with tcId: " << test_vector.id
        << " iv_size: " << test_vector.nonce.size()
        << " tag_size: " << test_vector.tag.size()
        << " key_size: " << key.size() << "; error: " << plaintext.status();
  }
}

INSTANTIATE_TEST_SUITE_P(XChacha20Poly1305BoringSslWycheproofTests,
                         XChacha20Poly1305BoringSslWycheproofTest,
                         ValuesIn(internal::ReadWycheproofTestVectors(
                             /*file_name=*/"xchacha20_poly1305_test.json")));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
