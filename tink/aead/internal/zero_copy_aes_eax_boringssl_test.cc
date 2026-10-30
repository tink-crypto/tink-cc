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

#include "tink/aead/internal/zero_copy_aes_eax_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead/aes_eax_key.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/aes_eax_test_vectors.h"
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

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::HasSubstr;
using ::testing::StartsWith;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

TEST(ZeroCopyAesEaxBoringSslTest, BasicZeroCopy) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  constexpr size_t kNonceSize = 12;
  constexpr size_t kTagSize = 16;
  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(kNonceSize)
          .SetTagSizeInBytes(kTagSize)
          .SetVariant(AesEaxParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<AesEaxKey> key = AesEaxKey::Create(
      *parameters,
      RestrictedData(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"),
                     InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> zc_cipher =
      AesEaxZeroCopyAead(*key);
  ASSERT_THAT(zc_cipher, IsOk());

  std::string message = "Some data to encrypt.";
  std::string associated_data = "Some data to authenticate.";

  EXPECT_EQ((*zc_cipher)->MaxEncryptionSize(message.size()),
            static_cast<int64_t>(message.size() + kNonceSize + kTagSize));
  for (int64_t ct_size = 0; ct_size <= int64_t{kNonceSize + kTagSize};
       ++ct_size) {
    EXPECT_EQ((*zc_cipher)->MaxDecryptionSize(ct_size), 0);
  }

  std::string ciphertext((*zc_cipher)->MaxEncryptionSize(message.size()), '\0');
  EXPECT_THAT(
      (*zc_cipher)
          ->Encrypt(
              message, associated_data,
              absl::MakeSpan(ciphertext).subspan(0, ciphertext.size() - 1))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Encryption buffer too small")));
  EXPECT_THAT(
      (*zc_cipher)
          ->Encrypt(absl::string_view(ciphertext).substr(0, message.size()),
                    associated_data, absl::MakeSpan(ciphertext))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Plaintext and output buffer must not overlap")));

  ASSERT_THAT(
      (*zc_cipher)
          ->Encrypt(message, associated_data, absl::MakeSpan(ciphertext)),
      IsOkAndHolds<int64_t>(ciphertext.size()));

  std::string plaintext((*zc_cipher)->MaxDecryptionSize(ciphertext.size()),
                        '\0');
  EXPECT_THAT(
      (*zc_cipher)
          ->Decrypt(ciphertext, associated_data,
                    absl::MakeSpan(plaintext).subspan(0, plaintext.size() - 1))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Decryption buffer too small")));
  EXPECT_THAT(
      (*zc_cipher)
          ->Decrypt(ciphertext, associated_data,
                    absl::MakeSpan(ciphertext).subspan(0, message.size()))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Ciphertext and output buffer must not overlap")));

  ASSERT_THAT(
      (*zc_cipher)
          ->Decrypt(ciphertext, associated_data, absl::MakeSpan(plaintext)),
      IsOkAndHolds(static_cast<int64_t>(message.size())));
  EXPECT_EQ(plaintext, message);
}

TEST(ZeroCopyAesEaxBoringSslFipsTest, FailsOnFipsOnlyMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  const AeadTestVector& test_vector =
      GetAesEaxTestVector(16, AesEaxParameters::Variant::kTink);
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(*test_vector.aead_key);
  EXPECT_THAT(AesEaxZeroCopyAead(key).status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("FIPS")));
}

class ZeroCopyAesEaxBoringSslTestVectorTest
    : public TestWithParam<AeadTestVector> {
 protected:
  void SetUp() override {
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Not supported in FIPS-only mode";
    }
  }
};

TEST_P(ZeroCopyAesEaxBoringSslTestVectorTest, Decrypt) {
  const AeadTestVector& test_vector = GetParam();
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      AesEaxZeroCopyAead(key);
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

TEST_P(ZeroCopyAesEaxBoringSslTestVectorTest, EncryptDecrypt) {
  const AeadTestVector& test_vector = GetParam();
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      AesEaxZeroCopyAead(key);
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

INSTANTIATE_TEST_SUITE_P(ZeroCopyAesEaxBoringSslTestVectorTests,
                         ZeroCopyAesEaxBoringSslTestVectorTest,
                         ValuesIn(CreateAesEaxTestVectors()));

TEST(ZeroCopyAesEaxBoringSslKeyTest, DecryptWithBadPrefixFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  const AeadTestVector& test_vector =
      GetAesEaxTestVector(16, AesEaxParameters::Variant::kTink);
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      AesEaxZeroCopyAead(key);
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
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Prefix mismatch")));
}

TEST(ZeroCopyAesEaxBoringSslKeyTest, DecryptWithShortPrefixedCiphertextFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  const AeadTestVector& test_vector =
      GetAesEaxTestVector(16, AesEaxParameters::Variant::kTink);
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      AesEaxZeroCopyAead(key);
  ASSERT_THAT(cipher, IsOk());

  const size_t min_size = key.GetOutputPrefix().size() +
                          key.GetParameters().GetIvSizeInBytes() +
                          key.GetParameters().GetTagSizeInBytes();
  EXPECT_EQ((*cipher)->MaxDecryptionSize(min_size), 0);
  std::string short_ciphertext(min_size - 1, 'a');
  std::string plaintext;
  EXPECT_THAT((*cipher)
                  ->Decrypt(short_ciphertext, test_vector.associated_data,
                            absl::MakeSpan(plaintext))
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Ciphertext too short")));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
