// Copyright 2017 Google LLC
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

#include "tink/subtle/aes_eax_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead.h"
#include "tink/aead/aes_eax_key.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/internal/aead_from_zero_copy.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/aes_eax_test_vectors.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/testing/wycheproof_util.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::AeadTestVector;
using ::crypto::tink::internal::CreateAesEaxTestVectors;
using ::crypto::tink::internal::GetAesEaxTestVector;
using ::crypto::tink::internal::wycheproof_testing::GetBytesFromHexValue;
using ::crypto::tink::internal::wycheproof_testing::ReadTestVectorsV1;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::StartsWith;
using ::testing::Test;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

class AesEaxBoringSslTest : public testing::Test {
 protected:
  void SetUp() override {
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Not supported in FIPS-only mode";
    }
  }
};

TEST_F(AesEaxBoringSslTest, TestBasic) {
  SecretData key =
      SecretData(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  size_t nonce_size = 12;
  auto res = AesEaxBoringSsl::New(key, nonce_size);
  ASSERT_THAT(res, IsOk());
  auto cipher = std::move(res.value());
  std::string message = "Some data to encrypt.";
  std::string associated_data = "Some data to authenticate.";
  auto ct = cipher->Encrypt(message, associated_data);
  ASSERT_THAT(ct, IsOk());
  EXPECT_EQ(ct.value().size(), message.size() + nonce_size + 16);
  auto pt = cipher->Decrypt(ct.value(), associated_data);
  ASSERT_THAT(pt, IsOk());
  EXPECT_EQ(pt.value(), message);
}

TEST_F(AesEaxBoringSslTest, TestMessageSize) {
  SecretData key =
      SecretData(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  size_t nonce_size = 12;
  auto res = AesEaxBoringSsl::New(key, nonce_size);
  ASSERT_THAT(res, IsOk());
  auto cipher = std::move(res.value());
  for (size_t size = 0; size < 260; size++) {
    std::string message(size, 'x');
    std::string associated_data = "";
    auto ct = cipher->Encrypt(message, associated_data);
    ASSERT_THAT(ct, IsOk());
    EXPECT_EQ(ct.value().size(), message.size() + nonce_size + 16);
    auto pt = cipher->Decrypt(ct.value(), associated_data);
    ASSERT_THAT(pt, IsOk());
    EXPECT_EQ(pt.value(), message);
  }
}

TEST_F(AesEaxBoringSslTest, TestAssociatedDataSize) {
  SecretData key =
      SecretData(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  size_t nonce_size = 12;
  auto res = AesEaxBoringSsl::New(key, nonce_size);
  ASSERT_THAT(res, IsOk());
  auto cipher = std::move(res.value());
  for (size_t size = 0; size < 260; size++) {
    std::string message("Some message");
    std::string associated_data(size, 'x');
    auto ct = cipher->Encrypt(message, associated_data);
    ASSERT_THAT(ct, IsOk());
    EXPECT_EQ(ct.value().size(), message.size() + nonce_size + 16);
    auto pt = cipher->Decrypt(ct.value(), associated_data);
    ASSERT_THAT(pt, IsOk());
    EXPECT_EQ(pt.value(), message);
  }
}

TEST_F(AesEaxBoringSslTest, TestLongNonce) {
  SecretData key =
      SecretData(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  size_t nonce_size = 16;
  auto res = AesEaxBoringSsl::New(key, nonce_size);
  ASSERT_THAT(res, IsOk());
  auto cipher = std::move(res.value());
  std::string message = "Some data to encrypt.";
  std::string associated_data = "Some associated data.";
  auto ct = cipher->Encrypt(message, associated_data);
  ASSERT_THAT(ct, IsOk());
  EXPECT_EQ(ct.value().size(), message.size() + nonce_size + 16);
  auto pt = cipher->Decrypt(ct.value(), associated_data);
  ASSERT_THAT(pt, IsOk());
  EXPECT_EQ(pt.value(), message);
}

TEST_F(AesEaxBoringSslTest, TestModification) {
  size_t nonce_size = 12;
  SecretData key =
      SecretData(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto cipher = std::move(AesEaxBoringSsl::New(key, nonce_size).value());
  std::string message = "Some data to encrypt.";
  std::string associated_data = "Some data to authenticate.";
  std::string ct = cipher->Encrypt(message, associated_data).value();
  EXPECT_THAT(cipher->Decrypt(ct, associated_data), IsOk());
  // Modify the ciphertext
  for (size_t i = 0; i < ct.size() * 8; i++) {
    std::string modified_ct = ct;
    modified_ct[i / 8] ^= 1 << (i % 8);
    EXPECT_THAT(cipher->Decrypt(modified_ct, associated_data), Not(IsOk()))
        << i;
  }
  // Modify the associated data
  for (size_t i = 0; i < associated_data.size() * 8; i++) {
    std::string modified_associated_data = associated_data;
    modified_associated_data[i / 8] ^= 1 << (i % 8);
    auto decrypted = cipher->Decrypt(ct, modified_associated_data);
    EXPECT_THAT(decrypted, Not(IsOk())) << i << " pt:" << decrypted.value();
  }
  // Truncate the ciphertext
  for (size_t i = 0; i < ct.size(); i++) {
    std::string truncated_ct(ct, 0, i);
    EXPECT_THAT(cipher->Decrypt(truncated_ct, associated_data), Not(IsOk()))
        << i;
  }
}

TEST_F(AesEaxBoringSslTest, TestInvalidKeySizes) {
  size_t nonce_size = 12;
  for (int keysize = 0; keysize < 65; keysize++) {
    if (keysize == 16 || keysize == 32) {
      continue;
    }
    SecretData key(keysize, 'x');
    auto cipher = AesEaxBoringSsl::New(key, nonce_size);
    EXPECT_THAT(cipher, Not(IsOk()));
  }
}

TEST_F(AesEaxBoringSslTest, TestInvalidNonceSizes) {
  SecretData key =
      SecretData(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  for (size_t nonce_size = 0; nonce_size < 65; ++nonce_size) {
    if (nonce_size == 12 || nonce_size == 16) {
      continue;
    }
    EXPECT_THAT(AesEaxBoringSsl::New(key, nonce_size).status(),
                StatusIs(absl::StatusCode::kInvalidArgument))
        << "for nonce_size = " << nonce_size;
  }
}

TEST_F(AesEaxBoringSslTest, TestEmpty) {
  size_t nonce_size = 12;
  SecretData key =
      SecretData(test::HexDecodeOrDie("bedcfb5a011ebc84600fcb296c15af0d"));
  std::string nonce(test::HexDecodeOrDie("438a547a94ea88dce46c6c85"));
  // Expected tag is an empty string with an empty tag is encrypted with
  // the nonce above;
  std::string tag(test::HexDecodeOrDie("9607977cd7556b1dfedf0c73a35a5197"));
  std::string ciphertext = nonce + tag;
  auto res = AesEaxBoringSsl::New(key, nonce_size);
  ASSERT_THAT(res, IsOk());
  auto cipher = std::move(res.value());

  // Test decryption of the arguments above.
  std::string empty_string("");
  absl::string_view empty_string_view("");
  absl::string_view null_string_view;

  auto pt = cipher->Decrypt(ciphertext, empty_string);
  ASSERT_THAT(pt, IsOk());
  EXPECT_EQ(0, pt.value().size());

  pt = cipher->Decrypt(ciphertext, empty_string_view);
  ASSERT_THAT(pt, IsOk());
  EXPECT_EQ(0, pt.value().size());

  pt = cipher->Decrypt(ciphertext, null_string_view);
  ASSERT_THAT(pt, IsOk());
  EXPECT_EQ(0, pt.value().size());

  // Test encryption.
  auto ct = cipher->Encrypt(empty_string, empty_string);
  ASSERT_THAT(ct, IsOk());
  pt = cipher->Decrypt(ct.value(), empty_string);
  ASSERT_THAT(pt, IsOk());
  EXPECT_EQ(0, pt.value().size());

  ct = cipher->Encrypt(empty_string_view, empty_string_view);
  ASSERT_THAT(ct, IsOk());
  pt = cipher->Decrypt(ct.value(), empty_string);
  ASSERT_THAT(pt, IsOk());
  EXPECT_EQ(0, pt.value().size());

  ct = cipher->Encrypt(empty_string_view, empty_string_view);
  ASSERT_THAT(ct, IsOk());
  pt = cipher->Decrypt(ct.value(), empty_string);
  ASSERT_THAT(pt, IsOk());
  EXPECT_EQ(0, pt.value().size());

  ct = cipher->Encrypt(null_string_view, null_string_view);
  ASSERT_THAT(ct, IsOk());
  pt = cipher->Decrypt(ct.value(), empty_string);
  ASSERT_THAT(pt, IsOk());
  EXPECT_EQ(0, pt.value().size());
}

// Test with test vectors from project Wycheproof.
// AesEaxBoringSsl does not allow to pass in IVs. Therefore this test
// can only test decryption.
// Currently AesEaxBoringSsl is restricted to encryption with 12 byte
// IVs and 16 byte tags. Therefore it is necessary to skip tests with
// other parameter sizes.
bool WycheproofTest(const google::protobuf::Struct& parsed_input,
                    int expected_skipped_tests_groups) {
  int errors = 0;
  int skipped_test_groups = 0;
  const google::protobuf::Value& test_groups =
      parsed_input.fields().at("testGroups");
  for (const google::protobuf::Value& test_group :
       test_groups.list_value().values()) {
    const auto& test_group_fields = test_group.struct_value().fields();
    const size_t iv_size = (int)test_group_fields.at("ivSize").number_value();
    const size_t key_size = (int)test_group_fields.at("keySize").number_value();
    const size_t tag_size = (int)test_group_fields.at("tagSize").number_value();
    if (key_size != 128 && key_size != 256) {
      // Not supported
      skipped_test_groups++;
      continue;
    }
    if (iv_size != 128 && iv_size != 96) {
      // Not supported
      skipped_test_groups++;
      continue;
    }
    if (tag_size != 128) {
      // Not supported
      skipped_test_groups++;
      continue;
    }
    for (const google::protobuf::Value& test :
         test_group.struct_value().fields().at("tests").list_value().values()) {
      const auto& test_fields = test.struct_value().fields();
      SecretData key = SecretData(GetBytesFromHexValue(test_fields.at("key")));
      std::string iv = GetBytesFromHexValue(test_fields.at("iv"));
      std::string msg = GetBytesFromHexValue(test_fields.at("msg"));
      std::string ct = GetBytesFromHexValue(test_fields.at("ct"));
      std::string associated_data = GetBytesFromHexValue(test_fields.at("aad"));
      std::string tag = GetBytesFromHexValue(test_fields.at("tag"));
      std::string id = absl::StrCat(test_fields.at("tcId").number_value());
      std::string expected = test_fields.at("result").string_value();
      auto cipher = std::move(AesEaxBoringSsl::New(key, iv_size / 8).value());
      auto result = cipher->Decrypt(iv + ct + tag, associated_data);
      bool success = result.ok();
      if (success) {
        std::string decrypted = result.value();
        if (expected == "invalid") {
          ADD_FAILURE() << "decrypted invalid ciphertext:" << id;
          errors++;
        } else if (msg != decrypted) {
          ADD_FAILURE() << "Incorrect decryption:" << id;
          errors++;
        }
      } else {
        if (expected == "valid" || expected == "acceptable") {
          ADD_FAILURE() << "Could not decrypt test with tcId:" << id
                        << " iv_size:" << iv_size << " tag_size:" << tag_size
                        << " key_size:" << key_size
                        << " error:" << result.status();
          errors++;
        }
      }
    }
  }
  EXPECT_EQ(skipped_test_groups, expected_skipped_tests_groups);
  return errors == 0;
}

TEST_F(AesEaxBoringSslTest, TestVectors) {
  absl::StatusOr<google::protobuf::Struct> parsed_input =
      ReadTestVectorsV1("aes_eax_test.json");
  ASSERT_THAT(parsed_input, IsOk());
  ASSERT_TRUE(WycheproofTest(*parsed_input,
                             /* expected_skipped_tests_groups = */ 26));
}

TEST(AesEaxBoringSslFipsTest, TestFipsOnly) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  SecretData key128 =
      SecretData(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  SecretData key256 = SecretData(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));

  EXPECT_THAT(subtle::AesEaxBoringSsl::New(key128, 16).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(subtle::AesEaxBoringSsl::New(key256, 16).status(),
              StatusIs(absl::StatusCode::kInternal));

  const AeadTestVector& test_vector128 =
      GetAesEaxTestVector(16, AesEaxParameters::Variant::kTink);
  const AeadTestVector& test_vector256 =
      GetAesEaxTestVector(32, AesEaxParameters::Variant::kTink);
  EXPECT_THAT(subtle::AesEaxBoringSsl::New(
                  dynamic_cast<const AesEaxKey&>(*test_vector128.aead_key))
                  .status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(subtle::AesEaxBoringSsl::New(
                  dynamic_cast<const AesEaxKey&>(*test_vector256.aead_key))
                  .status(),
              StatusIs(absl::StatusCode::kInternal));
}

class AesEaxBoringSslTestVectorTest : public TestWithParam<AeadTestVector> {
 protected:
  void SetUp() override {
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Not supported in FIPS-only mode";
    }
  }
};

TEST_P(AesEaxBoringSslTestVectorTest, DecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = AesEaxBoringSsl::New(key);
  if (key.GetParameters().GetKeySizeInBytes() == 24) {
    EXPECT_THAT(aead.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                        HasSubstr("Invalid key size")));
    return;
  }
  ASSERT_THAT(aead, IsOk());

  EXPECT_THAT(
      (*aead)->Decrypt(test_vector.ciphertext, test_vector.associated_data),
      IsOkAndHolds(test_vector.plaintext));
}

TEST_P(AesEaxBoringSslTestVectorTest, EncryptDecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = AesEaxBoringSsl::New(key);
  if (key.GetParameters().GetKeySizeInBytes() == 24) {
    EXPECT_THAT(aead.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                        HasSubstr("Invalid key size")));
    return;
  }
  ASSERT_THAT(aead, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(test_vector.plaintext, test_vector.associated_data);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT(*ciphertext, StartsWith(key.GetOutputPrefix()));

  EXPECT_THAT((*aead)->Decrypt(*ciphertext, test_vector.associated_data),
              IsOkAndHolds(test_vector.plaintext));
}

INSTANTIATE_TEST_SUITE_P(AesEaxBoringSslTestVectorTests,
                         AesEaxBoringSslTestVectorTest,
                         ValuesIn(CreateAesEaxTestVectors()));

TEST_F(AesEaxBoringSslTest, Rejects24ByteAesKey) {
  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(24)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<AesEaxKey> key =
      AesEaxKey::Create(*parameters, RestrictedData(24),
                        /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(AesEaxBoringSsl::New(*key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid key size")));
}

TEST_F(AesEaxBoringSslTest,
       DecryptWithKeyFailsWithModifiedCiphertextOrAssociatedData) {
  const AeadTestVector& test_vector =
      GetAesEaxTestVector(16, AesEaxParameters::Variant::kTink);
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = AesEaxBoringSsl::New(key);
  ASSERT_THAT(aead, IsOk());

  const size_t prefix_size = key.GetOutputPrefix().size();
  const size_t min_ciphertext_size =
      prefix_size + key.GetParameters().GetIvSizeInBytes() +
      key.GetParameters().GetTagSizeInBytes();

  for (size_t i = 0; i < test_vector.ciphertext.size(); ++i) {
    std::string modified_ciphertext = test_vector.ciphertext;
    modified_ciphertext[i] ^= 0x01;
    EXPECT_THAT((*aead)
                    ->Decrypt(modified_ciphertext, test_vector.associated_data)
                    .status(),
                StatusIs(absl::StatusCode::kInvalidArgument,
                         HasSubstr(i < prefix_size ? "Prefix mismatch"
                                                   : "Authentication failed")));
  }

  EXPECT_THAT((*aead)
                  ->Decrypt(test_vector.ciphertext, "modified associated data")
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Authentication failed")));

  for (size_t len = 0; len < test_vector.ciphertext.size(); ++len) {
    EXPECT_THAT(
        (*aead)
            ->Decrypt(absl::string_view(test_vector.ciphertext).substr(0, len),
                      test_vector.associated_data)
            .status(),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr(len < min_ciphertext_size
                               ? "Ciphertext too short"
                               : "Authentication failed")));
  }
}

TEST_F(AesEaxBoringSslTest, TestZeroCopy) {
  SecretData key =
      SecretData(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  constexpr size_t kNonceSize = 12;
  constexpr size_t kTagSize = 16;
  absl::StatusOr<std::unique_ptr<Aead>> cipher =
      AesEaxBoringSsl::New(key, kNonceSize);
  ASSERT_THAT(cipher, IsOk());
  const internal::ZeroCopyAead* zc_cipher =
      internal::MaybeZeroCopyFromAead(**cipher);
  ASSERT_NE(zc_cipher, nullptr);

  std::string message = "Some data to encrypt.";
  std::string associated_data = "Some data to authenticate.";

  EXPECT_EQ(zc_cipher->MaxEncryptionSize(message.size()),
            message.size() + kNonceSize + kTagSize);
  for (int64_t ct_size = 0; ct_size <= int64_t{kNonceSize + kTagSize};
       ++ct_size) {
    EXPECT_EQ(zc_cipher->MaxDecryptionSize(ct_size), 0);
  }

  std::string ciphertext(zc_cipher->MaxEncryptionSize(message.size()), '\0');
  EXPECT_THAT(zc_cipher->Encrypt(
                  message, associated_data,
                  absl::MakeSpan(ciphertext).subspan(0, ciphertext.size() - 1)),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(zc_cipher->Encrypt(
                  absl::string_view(ciphertext).substr(0, message.size()),
                  associated_data, absl::MakeSpan(ciphertext)),
              StatusIs(absl::StatusCode::kInvalidArgument));

  ASSERT_THAT(
      zc_cipher->Encrypt(message, associated_data, absl::MakeSpan(ciphertext)),
      IsOkAndHolds<int64_t>(ciphertext.size()));

  std::string plaintext(zc_cipher->MaxDecryptionSize(ciphertext.size()), '\0');
  EXPECT_THAT(zc_cipher->Decrypt(
                  ciphertext, associated_data,
                  absl::MakeSpan(plaintext).subspan(0, plaintext.size() - 1)),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      zc_cipher->Decrypt(ciphertext, associated_data,
                         absl::MakeSpan(ciphertext).subspan(0, message.size())),
      StatusIs(absl::StatusCode::kInvalidArgument));

  ASSERT_THAT(zc_cipher->Decrypt(ciphertext, associated_data,
                                 absl::MakeSpan(plaintext)),
              IsOkAndHolds(message.size()));
  EXPECT_EQ(plaintext, message);
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
