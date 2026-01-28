// Copyright 2017 Google Inc.
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

#include "tink/subtle/aes_siv_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/testing/wycheproof_util.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::testing::Not;

using ::crypto::tink::internal::wycheproof_testing::GetBytesFromHexValue;
using ::crypto::tink::internal::wycheproof_testing::ReadTestVectorsV1;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

TEST(AesSivBoringSslTest, testCarryComputation) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  uint8_t value = 0;
  for (int i = 0; i < 256; i++) {
    uint8_t carry = static_cast<int8_t>(value) >> 7;
    if (i < 128) {
      EXPECT_EQ(carry, 0x00);
    } else {
      EXPECT_EQ(carry, 0xff);
    }
    value++;
  }
}

TEST(AesSivBoringSslTest, testEncryptDecrypt) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  SecretData key = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      "00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
  auto res = AesSivBoringSsl::New(key);
  ASSERT_THAT(res, IsOk());
  auto cipher = std::move(res.value());
  std::string associated_data = "Associated data";
  std::string message = "Some data to encrypt.";
  auto ct = cipher->EncryptDeterministically(message, associated_data);
  ASSERT_THAT(ct, IsOk());
  auto pt = cipher->DecryptDeterministically(ct.value(), associated_data);
  EXPECT_THAT(pt, IsOk());
  EXPECT_EQ(pt.value(), message);
}

TEST(AesSivBoringSslTest, testNullPtrStringView) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  SecretData key = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      "00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
  auto res = AesSivBoringSsl::New(key);
  ASSERT_THAT(res, IsOk());
  // Checks that a default constructed string_view works.
  auto cipher = std::move(res.value());
  absl::string_view null;
  auto ct = cipher->EncryptDeterministically(null, null);
  ASSERT_THAT(ct, IsOk());
  auto pt = cipher->DecryptDeterministically(ct.value(), null);
  EXPECT_THAT(pt, IsOk());
  EXPECT_EQ("", pt.value());
  // Decryption with ct == null should return an appropriate status.
  pt = cipher->DecryptDeterministically(null, "");
  EXPECT_THAT(pt, Not(IsOk()));
  // Associated data with an empty string view is the same an empty string.
  std::string message("123456789abcdefghijklmnop");
  ct = cipher->EncryptDeterministically(message, null);
  pt = cipher->DecryptDeterministically(ct.value(), "");
  EXPECT_THAT(pt, IsOk());
  EXPECT_EQ(message, pt.value());
  ct = cipher->EncryptDeterministically(message, "");
  pt = cipher->DecryptDeterministically(ct.value(), null);
  EXPECT_THAT(pt, IsOk());
  EXPECT_EQ(message, pt.value());
}

// Only 64 byte key sizes are supported.
TEST(AesSivBoringSslTest, testEncryptDecryptKeySizes) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  std::string keymaterial = test::HexDecodeOrDie(
      "198371900187498172316311acf81d238ff7619873a61983d619c87b63a1987f"
      "987131819803719b847126381cd763871638aa71638176328761287361231321"
      "812731321de508761437195ff231765aa4913219873ac6918639816312130011"
      "abc900bba11400187984719827431246bbab1231eb4145215ff7141436616beb"
      "9817298148712fed3aab61000ff123313e");
  for (size_t keysize = 0; keysize < keymaterial.size(); ++keysize) {
    SecretData key = util::SecretDataFromStringView(
        absl::string_view(keymaterial).substr(0, keysize));
    auto cipher = AesSivBoringSsl::New(key);
    if (keysize == 64) {
      EXPECT_THAT(cipher, IsOk());
    } else {
      EXPECT_THAT(cipher, Not(IsOk()))
          << "Accepted invalid key size:" << keysize;
    }
  }
}

// Checks a range of message sizes.
TEST(AesSivBoringSslTest, testEncryptDecryptMessageSize) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  SecretData key = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      "00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
  auto res = AesSivBoringSsl::New(key);
  ASSERT_THAT(res, IsOk());
  auto cipher = std::move(res.value());
  std::string associated_data = "Associated data";
  for (int i = 0; i < 1024; ++i) {
    std::string message = std::string(i, 'a');
    auto ct = cipher->EncryptDeterministically(message, associated_data);
    ASSERT_THAT(ct, IsOk());
    auto pt = cipher->DecryptDeterministically(ct.value(), associated_data);
    EXPECT_THAT(pt, IsOk());
    EXPECT_EQ(pt.value(), message);
  }
  for (int i = 1024; i < 100000; i += 5000) {
    std::string message = std::string(i, 'a');
    auto ct = cipher->EncryptDeterministically(message, associated_data);
    ASSERT_THAT(ct, IsOk());
    auto pt = cipher->DecryptDeterministically(ct.value(), associated_data);
    EXPECT_THAT(pt, IsOk());
    EXPECT_EQ(pt.value(), message);
  }
}

// Checks a range of associated_data sizes.
TEST(AesSivBoringSslTest, testEncryptDecryptAssociatedDataSize) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  SecretData key = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      "00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
  auto res = AesSivBoringSsl::New(key);
  ASSERT_THAT(res, IsOk());
  auto cipher = std::move(res.value());
  std::string message = "Some plaintext";
  for (int i = 0; i < 1028; ++i) {
    std::string associated_data = std::string(i, 'a');
    auto ct = cipher->EncryptDeterministically(message, associated_data);
    ASSERT_THAT(ct, IsOk());
    auto pt = cipher->DecryptDeterministically(ct.value(), associated_data);
    EXPECT_THAT(pt, IsOk());
    EXPECT_EQ(pt.value(), message);
  }
}

TEST(AesSivBoringSslTest, testDecryptModification) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  SecretData key = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      "00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
  auto res = AesSivBoringSsl::New(key);
  ASSERT_THAT(res, IsOk());
  auto cipher = std::move(res.value());
  std::string associated_data = "Associated data";
  for (int i = 0; i < 50; ++i) {
    std::string message = std::string(i, 'a');
    auto ct = cipher->EncryptDeterministically(message, associated_data);
    ASSERT_THAT(ct, IsOk());
    std::string ciphertext = ct.value();
    for (size_t b = 0; b < ciphertext.size(); ++b) {
      for (int bit = 0; bit < 8; ++bit) {
        std::string modified = ciphertext;
        modified[b] ^= (1 << bit);
        auto pt = cipher->DecryptDeterministically(modified, associated_data);
        EXPECT_THAT(pt, Not(IsOk())) << "Modified ciphertext decrypted."
                                     << " byte:" << b << " bit:" << bit;
      }
    }
  }
}

// Test with test vectors from project Wycheproof.
void WycheproofTest(const google::protobuf::Struct& parsed_input,
                    int expected_skipped_tests_groups) {
  int skipped_test_groups = 0;
  const google::protobuf::Value& test_groups =
      parsed_input.fields().at("testGroups");
  for (const google::protobuf::Value& test_group :
       test_groups.list_value().values()) {
    const auto& test_group_fields = test_group.struct_value().fields();
    const size_t key_size = test_group_fields.at("keySize").number_value();
    if (!AesSivBoringSsl::IsValidKeySizeInBytes(key_size / 8)) {
      // Currently the key size is restricted to two 256-bit AES keys.
      skipped_test_groups++;
      continue;
    }
    for (const google::protobuf::Value& test :
         test_group.struct_value().fields().at("tests").list_value().values()) {
      auto test_fields = test.struct_value().fields();
      std::string comment = test_fields.at("comment").string_value();
      SecretData key = util::SecretDataFromStringView(
          GetBytesFromHexValue(test_fields.at("key")));
      std::string msg = GetBytesFromHexValue(test_fields.at("msg"));
      std::string ct = GetBytesFromHexValue(test_fields.at("ct"));
      std::string associated_data = GetBytesFromHexValue(test_fields.at("aad"));
      int id = (int)test_fields.at("tcId").number_value();
      std::string result = test_fields.at("result").string_value();
      auto cipher = std::move(AesSivBoringSsl::New(key).value());

      // Test encryption.
      // Encryption should always succeed since msg and aad are valid inputs.
      std::string encrypted =
          cipher->EncryptDeterministically(msg, associated_data).value();
      std::string encrypted_hex = test::HexEncode(encrypted);
      std::string ct_hex = test::HexEncode(ct);
      if (result == "valid" || result == "acceptable") {
        EXPECT_EQ(ct_hex, encrypted_hex)
            << "incorrect encryption: " << id << " " << comment;
      } else {
        EXPECT_NE(ct_hex, encrypted_hex)
            << "invalid encryption: " << id << " " << comment;
      }

      // Test decryption
      auto decrypted = cipher->DecryptDeterministically(ct, associated_data);
      if (decrypted.ok()) {
        if (result == "invalid") {
          ADD_FAILURE() << "decrypted invalid ciphertext:" << id;
        } else {
          EXPECT_EQ(test::HexEncode(msg), test::HexEncode(decrypted.value()))
              << "incorrect decryption: " << id << " " << comment;
        }
      } else {
        EXPECT_NE(result, "valid")
            << "failed to decrypt: " << id << " " << comment;
      }
    }
  }
  EXPECT_EQ(skipped_test_groups, expected_skipped_tests_groups);
}

TEST(AesSivBoringSslTest, TestVectors) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  absl::StatusOr<google::protobuf::Struct> parsed_input =
      ReadTestVectorsV1("aes_siv_cmac_test.json");
  ASSERT_THAT(parsed_input, IsOk());
  WycheproofTest(*parsed_input, /*expected_skipped_tests_groups=*/2);
}

TEST(AesSivBoringSslTest, TestFipsOnly) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  SecretData key128 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  SecretData key256 = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));

  EXPECT_THAT(subtle::AesSivBoringSsl::New(key128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(subtle::AesSivBoringSsl::New(key256).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
