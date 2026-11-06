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

#include "tink/subtle/aes_gcm_boringssl.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/aes_gcm_test_vectors.h"
#include "tink/aead/internal/wycheproof_aead.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

constexpr absl::string_view kMessage = "Some data to encrypt.";
constexpr absl::string_view kAssociatedData = "Some associated data.";
constexpr absl::string_view kKey128 = "000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kKey256 =
    "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::AeadTestVector;
using ::crypto::tink::internal::CreateAesGcmTestVectors;
using ::crypto::tink::internal::GetAesGcmTestVector;
using ::testing::AnyOf;
using ::testing::Eq;
using ::testing::Not;
using ::testing::StartsWith;
using ::testing::Test;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

class AesGcmBoringSslTest : public Test {
 protected:
  void SetUp() override {
    if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
      GTEST_SKIP() << "Test should not run in FIPS mode when BoringCrypto is "
                      "unavailable.";
    }

    SecretData key =
        util::SecretDataFromStringView(test::HexDecodeOrDie(kKey128));
    absl::StatusOr<std::unique_ptr<Aead>> cipher = AesGcmBoringSsl::New(key);
    ASSERT_THAT(cipher, IsOk());
    cipher_ = std::move(*cipher);
  }
  std::unique_ptr<Aead> cipher_;
};

TEST_F(AesGcmBoringSslTest, BasicEncryptDecrypt) {
  absl::StatusOr<std::string> ciphertext =
      cipher_->Encrypt(kMessage, kAssociatedData);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_EQ(ciphertext->size(), kMessage.size() + 12 + 16);
  absl::StatusOr<std::string> plaintext =
      cipher_->Decrypt(*ciphertext, kAssociatedData);
  ASSERT_THAT(plaintext, IsOk());
  EXPECT_EQ(*plaintext, kMessage);
}

TEST_F(AesGcmBoringSslTest, ModifyMessageAndAssociatedData) {
  absl::StatusOr<std::string> ciphertext =
      cipher_->Encrypt(kMessage, kAssociatedData);
  ASSERT_THAT(ciphertext, IsOk());
  ASSERT_THAT(cipher_->Decrypt(*ciphertext, kAssociatedData), IsOk());
  // Modify the ciphertext.
  for (size_t i = 0; i < ciphertext->size() * 8; i++) {
    std::string modified_ct = *ciphertext;
    modified_ct[i / 8] ^= 1 << (i % 8);
    EXPECT_THAT(cipher_->Decrypt(modified_ct, kAssociatedData).status(),
                Not(IsOk()))
        << i;
  }
  // Modify the associated  data.
  for (size_t i = 0; i < kAssociatedData.size() * 8; i++) {
    std::string modified_ad = std::string(kAssociatedData);
    modified_ad[i / 8] ^= 1 << (i % 8);
    auto decrypted = cipher_->Decrypt(*ciphertext, modified_ad);
    EXPECT_THAT(decrypted, Not(IsOk())) << i << " pt:" << *decrypted;
  }
  // Truncate the ciphertext.
  for (size_t i = 0; i < ciphertext->size(); i++) {
    std::string truncated_ct(*ciphertext, 0, i);
    EXPECT_THAT(cipher_->Decrypt(truncated_ct, kAssociatedData).status(),
                Not(IsOk()))
        << i;
  }
}

void TestDecryptWithEmptyAssociatedData(Aead* cipher, absl::string_view ct,
                             absl::string_view message) {
  {  // associated_data is a null string_view.
    const absl::string_view associated_data;
    absl::StatusOr<std::string> plaintext =
        cipher->Decrypt(ct, associated_data);
    EXPECT_THAT(plaintext, IsOk());
    EXPECT_EQ(message, *plaintext);
  }
  {  // associated_data is a an empty string.
    absl::StatusOr<std::string> plaintext = cipher->Decrypt(ct, "");
    EXPECT_THAT(plaintext, IsOk());
    EXPECT_EQ(message, *plaintext);
  }
  {  // associated_data is a default constructed string_view.
    absl::StatusOr<std::string> plaintext =
        cipher->Decrypt(ct, absl::string_view());
    EXPECT_THAT(plaintext, IsOk());
    EXPECT_EQ(message, *plaintext);
  }
}

TEST_F(AesGcmBoringSslTest, AssociatedDataEmptyVersusNullStringView) {
  {
    // associated_data is a null string_view.
    const absl::string_view associated_data;
    auto ciphertext = cipher_->Encrypt(kMessage, associated_data);
    EXPECT_THAT(ciphertext, IsOk());
    TestDecryptWithEmptyAssociatedData(cipher_.get(), *ciphertext, kMessage);
  }
  {  // associated_data is a an empty string.
    auto ciphertext = cipher_->Encrypt(kMessage, "");
    EXPECT_THAT(ciphertext, IsOk());
    TestDecryptWithEmptyAssociatedData(cipher_.get(), *ciphertext, kMessage);
  }
  {  // associated_data is a default constructed string_view.
    auto ciphertext = cipher_->Encrypt(kMessage, absl::string_view());
    EXPECT_THAT(ciphertext, IsOk());
    TestDecryptWithEmptyAssociatedData(cipher_.get(), *ciphertext, kMessage);
  }
}

TEST_F(AesGcmBoringSslTest, MessageEmptyVersusNullStringView) {
  {  // Message is a null string_view.
    const absl::string_view message;
    absl::StatusOr<std::string> ciphertext =
        cipher_->Encrypt(message, kAssociatedData);
    ASSERT_THAT(ciphertext, IsOk());
    auto plaintext = cipher_->Decrypt(*ciphertext, kAssociatedData);
    ASSERT_THAT(plaintext, IsOk());
    EXPECT_EQ(*plaintext, "");
  }
  {  // Message is an empty string.
    const std::string message = "";
    absl::StatusOr<std::string> ciphertext =
        cipher_->Encrypt(message, kAssociatedData);
    ASSERT_THAT(ciphertext, IsOk());
    auto plaintext = cipher_->Decrypt(*ciphertext, kAssociatedData);
    ASSERT_THAT(plaintext, IsOk());
    EXPECT_EQ(*plaintext, "");
  }
  {  // Message is a default constructed string_view.
    absl::StatusOr<std::string> ciphertext =
        cipher_->Encrypt(absl::string_view(), kAssociatedData);
    ASSERT_THAT(ciphertext, IsOk());
    auto plaintext = cipher_->Decrypt(*ciphertext, kAssociatedData);
    ASSERT_THAT(plaintext, IsOk());
    EXPECT_EQ(*plaintext, "");
  }
}

TEST_F(AesGcmBoringSslTest, BothMessageAndAssociatedDataEmpty) {
  {  // Both are null string_view.
    const absl::string_view message;
    const absl::string_view associated_data;
    absl::StatusOr<std::string> ciphertext =
        cipher_->Encrypt(message, associated_data);
    ASSERT_THAT(ciphertext, IsOk());
    auto plaintext = cipher_->Decrypt(*ciphertext, associated_data);
    ASSERT_THAT(plaintext, IsOk());
    EXPECT_EQ(*plaintext, "");
  }
  {  // Both are empty string.
    const std::string message = "";
    const std::string associated_data = "";
    absl::StatusOr<std::string> ciphertext =
        cipher_->Encrypt(message, associated_data);
    ASSERT_THAT(ciphertext, IsOk());
    auto plaintext = cipher_->Decrypt(*ciphertext, associated_data);
    ASSERT_THAT(plaintext, IsOk());
    EXPECT_EQ(*plaintext, "");
  }
  {  // Both are default constructed string_view.
    absl::StatusOr<std::string> ciphertext =
        cipher_->Encrypt(absl::string_view(), absl::string_view());
    ASSERT_THAT(ciphertext, IsOk());
    auto plaintext = cipher_->Decrypt(*ciphertext, absl::string_view());
    ASSERT_THAT(plaintext, IsOk());
    EXPECT_EQ(*plaintext, "");
  }
}

TEST_F(AesGcmBoringSslTest, InvalidKeySizes) {
  for (int keysize = 0; keysize < 65; keysize++) {
    SecretData key(keysize, 'x');
    absl::StatusOr<std::unique_ptr<crypto::tink::Aead>> cipher =
        AesGcmBoringSsl::New(key);
    if (keysize == 16 || keysize == 32) {
      EXPECT_THAT(cipher, IsOk());
    } else {
      EXPECT_THAT(cipher, Not(IsOk()));
    }
  }
}

TEST(AesGcmBoringSslFipsTest, FipsOnly) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  SecretData key_128 =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKey128));
  SecretData key_256 =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKey256));

  EXPECT_THAT(AesGcmBoringSsl::New(key_128), IsOk());
  EXPECT_THAT(AesGcmBoringSsl::New(key_256), IsOk());

  const AeadTestVector& test_vector_128 =
      GetAesGcmTestVector(16, AesGcmParameters::Variant::kTink);
  const AeadTestVector& test_vector_256 =
      GetAesGcmTestVector(32, AesGcmParameters::Variant::kTink);
  EXPECT_THAT(AesGcmBoringSsl::New(
                  dynamic_cast<const AesGcmKey&>(*test_vector_128.aead_key)),
              IsOk());
  EXPECT_THAT(AesGcmBoringSsl::New(
                  dynamic_cast<const AesGcmKey&>(*test_vector_256.aead_key)),
              IsOk());
}

TEST(AesGcmBoringSslFipsTest, FipsFailWithoutBoringCrypto) {
  if (!internal::IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  SecretData key_128 =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKey128));
  SecretData key_256 =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKey256));

  EXPECT_THAT(AesGcmBoringSsl::New(key_128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(AesGcmBoringSsl::New(key_256).status(),
              StatusIs(absl::StatusCode::kInternal));

  const AeadTestVector& test_vector_128 =
      GetAesGcmTestVector(16, AesGcmParameters::Variant::kTink);
  const AeadTestVector& test_vector_256 =
      GetAesGcmTestVector(32, AesGcmParameters::Variant::kTink);
  EXPECT_THAT(AesGcmBoringSsl::New(
                  dynamic_cast<const AesGcmKey&>(*test_vector_128.aead_key))
                  .status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(AesGcmBoringSsl::New(
                  dynamic_cast<const AesGcmKey&>(*test_vector_256.aead_key))
                  .status(),
              StatusIs(absl::StatusCode::kInternal));
}

class AesGcmBoringSslTestVectorTest : public TestWithParam<AeadTestVector> {
 protected:
  void SetUp() override {
    if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
      GTEST_SKIP() << "Test should not run in FIPS mode when BoringCrypto is "
                      "unavailable.";
    }
  }
};

TEST_P(AesGcmBoringSslTestVectorTest, DecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const AesGcmKey& key = dynamic_cast<const AesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = AesGcmBoringSsl::New(key);
  ASSERT_THAT(aead, IsOk());

  EXPECT_THAT(
      (*aead)->Decrypt(test_vector.ciphertext, test_vector.associated_data),
      IsOkAndHolds(test_vector.plaintext));
}

TEST_P(AesGcmBoringSslTestVectorTest, EncryptDecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const AesGcmKey& key = dynamic_cast<const AesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = AesGcmBoringSsl::New(key);
  ASSERT_THAT(aead, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(test_vector.plaintext, test_vector.associated_data);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT(*ciphertext, StartsWith(key.GetOutputPrefix()));

  EXPECT_THAT((*aead)->Decrypt(*ciphertext, test_vector.associated_data),
              IsOkAndHolds(test_vector.plaintext));
}

INSTANTIATE_TEST_SUITE_P(AesGcmBoringSslTestVectorTests,
                         AesGcmBoringSslTestVectorTest,
                         ValuesIn(CreateAesGcmTestVectors()));

TEST_F(AesGcmBoringSslTest, Rejects24ByteAesKey) {
  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(24)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<AesGcmKey> key =
      AesGcmKey::Create(*parameters, RestrictedData(24),
                        /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(AesGcmBoringSsl::New(*key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesGcmBoringSslTest, RejectsInvalidIvSize) {
  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<AesGcmKey> key =
      AesGcmKey::Create(*parameters, RestrictedData(16),
                        /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(AesGcmBoringSsl::New(*key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesGcmBoringSslTest, RejectsInvalidTagSize) {
  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(12)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<AesGcmKey> key =
      AesGcmKey::Create(*parameters, RestrictedData(16),
                        /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(AesGcmBoringSsl::New(*key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesGcmBoringSslTest,
       DecryptWithKeyFailsWithModifiedCiphertextOrAssociatedData) {
  const AeadTestVector& test_vector =
      GetAesGcmTestVector(16, AesGcmParameters::Variant::kTink);
  const AesGcmKey& key = dynamic_cast<const AesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = AesGcmBoringSsl::New(key);
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

class AesGcmBoringSslWycheproofTest
    : public TestWithParam<internal::WycheproofTestVector> {
  void SetUp() override {
    if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
      GTEST_SKIP() << "Test should not run in FIPS mode when BoringCrypto is "
                      "unavailable.";
    }
    internal::WycheproofTestVector test_vector = GetParam();
    if ((test_vector.key.size() != 16 && test_vector.key.size() != 32) ||
        test_vector.nonce.size() != 12 || test_vector.tag.size() != 16) {
      GTEST_SKIP() << "Unsupported parameters: key size "
                   << test_vector.key.size()
                   << " nonce size: " << test_vector.nonce.size()
                   << " tag size: " << test_vector.tag.size();
    }
  }
};

TEST_P(AesGcmBoringSslWycheproofTest, Decrypt) {
  internal::WycheproofTestVector test_vector = GetParam();
  SecretData key = util::SecretDataFromStringView(test_vector.key);
  absl::StatusOr<std::unique_ptr<Aead>> cipher = AesGcmBoringSsl::New(key);
  ASSERT_THAT(cipher, IsOk());
  std::string ciphertext =
      absl::StrCat(test_vector.nonce, test_vector.ct, test_vector.tag);
  absl::StatusOr<std::string> plaintext =
      (*cipher)->Decrypt(ciphertext, test_vector.aad);
  if (plaintext.ok()) {
    EXPECT_NE(test_vector.expected, "invalid");
    EXPECT_EQ(*plaintext, test_vector.msg);
  } else {
    EXPECT_THAT(test_vector.expected, Not(AnyOf(Eq("valid"), Eq("acceptable"))))
        << "Could not decrypt test with tcId: " << test_vector.id
        << " iv_size: " << test_vector.nonce.size()
        << " tag_size: " << test_vector.tag.size()
        << " key_size: " << key.size() << "; error: " << plaintext.status();
  }
}

INSTANTIATE_TEST_SUITE_P(AesGcmBoringSslWycheproofTests,
                         AesGcmBoringSslWycheproofTest,
                         ValuesIn(internal::ReadWycheproofTestVectors(
                             /*file_name=*/"aes_gcm_test.json")));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
