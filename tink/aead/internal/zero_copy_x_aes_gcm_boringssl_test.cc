// Copyright 2024 Google LLC
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

#include "tink/aead/internal/zero_copy_x_aes_gcm_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/aead/x_aes_gcm_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataFromStringView;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;

constexpr int kDefaultSaltSize = 12;
constexpr int kKeySize = 32;

absl::StatusOr<XAesGcmKey> CreateKey(absl::string_view key, int salt_size) {
  absl::StatusOr<XAesGcmParameters> parameters = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kNoPrefix, salt_size);
  if (!parameters.ok()) {
    return parameters.status();
  }
  return XAesGcmKey::Create(*parameters,
                            RestrictedData(SecretDataFromStringView(key),
                                           InsecureSecretKeyAccess::Get()),
                            absl::nullopt, GetPartialKeyAccess());
}

absl::StatusOr<XAesGcmKey> CreateKey(int salt_size) {
  return CreateKey(Random::GetRandomBytes(kKeySize), salt_size);
}

TEST(XAesGcmBoringSslZeroCopyAead, EncryptDecrypt) {
  absl::StatusOr<XAesGcmKey> key = CreateKey(kDefaultSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> zero_copy_aead =
      NewZeroCopyXAesGcmBoringSsl(*key);
  ASSERT_THAT(zero_copy_aead, IsOk());

  std::string aad = "aad";
  std::string pt = Random::GetRandomBytes(1024);
  int ct_size = (*zero_copy_aead)->MaxEncryptionSize(pt.size());
  std::string ct(ct_size, 0);

  absl::StatusOr<int64_t> n =
      (*zero_copy_aead)->Encrypt(pt, aad, absl::MakeSpan(ct));
  ASSERT_THAT(n, IsOk());
  ASSERT_THAT(*n, Eq(ct.size()));

  std::string recovered((*zero_copy_aead)->MaxDecryptionSize(ct.size()), 0);
  n = (*zero_copy_aead)->Decrypt(ct, aad, absl::MakeSpan(recovered));
  ASSERT_THAT(n, IsOk());
  ASSERT_THAT(*n, Eq(pt.size()));
  ASSERT_THAT(recovered, Eq(pt));
}

TEST(XAesGcmBoringSslZeroCopyAead, EncryptWithInsufficientBufferSizeFails) {
  absl::StatusOr<XAesGcmKey> key = CreateKey(kDefaultSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> zero_copy_aead =
      NewZeroCopyXAesGcmBoringSsl(*key);
  ASSERT_THAT(zero_copy_aead, IsOk());

  std::string aad = "aad";
  std::string pt = Random::GetRandomBytes(1024);
  std::string ct((*zero_copy_aead)->MaxEncryptionSize(pt.size()) - 1, 0);

  absl::StatusOr<int64_t> n =
      (*zero_copy_aead)->Encrypt(pt, aad, absl::MakeSpan(ct));
  EXPECT_THAT(n, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(XAesGcmBoringSslZeroCopyAead, DecryptWithSmallCiphertextFails) {
  absl::StatusOr<XAesGcmKey> key = CreateKey(kDefaultSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> zero_copy_aead =
      NewZeroCopyXAesGcmBoringSsl(*key);
  ASSERT_THAT(zero_copy_aead, IsOk());

  std::string ct(2, 0);
  std::string aad = "aad";
  std::string recovered((*zero_copy_aead)->MaxDecryptionSize(ct.size()), 0);
  absl::StatusOr<int64_t> n =
      (*zero_copy_aead)->Decrypt(ct, aad, absl::MakeSpan(recovered));
  EXPECT_THAT(n, StatusIs(absl::StatusCode::kInvalidArgument,
                          HasSubstr("Ciphertext too short")));
}

TEST(XAesGcmBoringSslZeroCopyAead, MaxDecryptionSizeIsZeroOrPossitive) {
  absl::StatusOr<XAesGcmKey> key = CreateKey(kDefaultSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> zero_copy_aead =
      NewZeroCopyXAesGcmBoringSsl(*key);
  ASSERT_THAT(zero_copy_aead, IsOk());
  EXPECT_THAT((*zero_copy_aead)->MaxDecryptionSize(1), Eq(0));
}

TEST(XAesGcmBoringSslZeroCopyAead, DecryptWithInsufficientBufferSizeFails) {
  absl::StatusOr<XAesGcmKey> key = CreateKey(kDefaultSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> zero_copy_aead =
      NewZeroCopyXAesGcmBoringSsl(*key);
  ASSERT_THAT(zero_copy_aead, IsOk());

  std::string aad = "aad";
  std::string pt = Random::GetRandomBytes(1024);
  int ct_size = (*zero_copy_aead)->MaxEncryptionSize(pt.size());
  std::string ct(ct_size, 0);

  absl::StatusOr<int64_t> n =
      (*zero_copy_aead)->Encrypt(pt, aad, absl::MakeSpan(ct));
  ASSERT_THAT(n, IsOk());
  ASSERT_THAT(*n, Eq(ct.size()));

  std::string recovered((*zero_copy_aead)->MaxDecryptionSize(ct.size()) - 1, 0);
  n = (*zero_copy_aead)->Decrypt(ct, aad, absl::MakeSpan(recovered));
  EXPECT_THAT(n, StatusIs(absl::StatusCode::kInvalidArgument));
}

struct XAesGcmTestVector {
  std::string name;
  std::string hex_key;
  std::string nonce;
  std::string aad;
  std::string plaintext;
  std::string hex_ciphertext;
  int salt_size;
};

using XAesGcmTestVectors = TestWithParam<XAesGcmTestVector>;

// Test vectors from
// https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md#test-vectors.
std::vector<XAesGcmTestVector> GetTestVectors() {
  return {
      {
          /*name=*/"test_vector_1",
          /*hex_key=*/
          "0101010101010101010101010101010101010101010101010101010101010101",
          /*nonce=*/"ABCDEFGHIJKLMNOPQRSTUVWX",
          /*aad=*/"",
          /*plaintext=*/"XAES-256-GCM",
          /*hex_ciphertext=*/
          "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271",
          /*salt_size=*/12,
      },
      {
          /*name=*/"test_vector_2",
          /*hex_key=*/
          "0303030303030303030303030303030303030303030303030303030303030303",
          /*nonce=*/"ABCDEFGHIJKLMNOPQRSTUVWX",
          /*aad=*/"c2sp.org/XAES-256-GCM",
          /*plaintext=*/"XAES-256-GCM",
          /*hex_ciphertext=*/
          "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d",
          /*salt_size=*/12,
      },
  };
}

TEST_P(XAesGcmTestVectors, DecryptKnownTestVectors) {
  const XAesGcmTestVector& test_case = GetParam();
  absl::StatusOr<XAesGcmKey> key =
      CreateKey(test::HexDecodeOrDie(test_case.hex_key), kDefaultSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> zero_copy_aead =
      NewZeroCopyXAesGcmBoringSsl(*key);
  ASSERT_THAT(zero_copy_aead, IsOk());

  std::string ct = absl::StrCat(test_case.nonce,
                                test::HexDecodeOrDie(test_case.hex_ciphertext));

  std::string recovered((*zero_copy_aead)->MaxDecryptionSize(ct.size()), 0);
  absl::StatusOr<int64_t> n =
      (*zero_copy_aead)->Decrypt(ct, test_case.aad, absl::MakeSpan(recovered));
  ASSERT_THAT(n, IsOk());
  ASSERT_THAT(*n, Eq(test_case.plaintext.size()));
  ASSERT_THAT(recovered, Eq(test_case.plaintext));
}

INSTANTIATE_TEST_SUITE_P(
    XAesGcmTestVectors, XAesGcmTestVectors, testing::ValuesIn(GetTestVectors()),
    [](const testing::TestParamInfo<XAesGcmTestVectors::ParamType>& info) {
      return info.param.name;
    });

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
