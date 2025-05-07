// Copyright 2024 Google LLC
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

#include "tink/aead/internal/cord_x_aes_gcm_boringssl.h"

#include <memory>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/cord.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/aead/x_aes_gcm_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::TestWithParam;

constexpr int kKeySize = 32;
constexpr int kMinSaltSize = 8;
constexpr int kMaxSaltSize = 12;
constexpr int kIvSize = 12;
constexpr int kCtOverhead = kIvSize + 16;

absl::StatusOr<XAesGcmKey> CreateKey(absl::string_view key, int salt_size) {
  absl::StatusOr<XAesGcmParameters> parameters = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kNoPrefix, salt_size);
  if (!parameters.ok()) {
    return parameters.status();
  }
  return XAesGcmKey::Create(*parameters,
                            RestrictedData(util::SecretDataFromStringView(key),
                                           InsecureSecretKeyAccess::Get()),
                            absl::nullopt, GetPartialKeyAccess());
}

absl::StatusOr<XAesGcmKey> CreateKey(int salt_size) {
  return CreateKey(Random::GetRandomBytes(kKeySize), salt_size);
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
      CreateKey(test::HexDecodeOrDie(test_case.hex_key), test_case.salt_size);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<CordAead>> aead =
      NewCordXAesGcmBoringSsl(*key);
  ASSERT_THAT(aead, IsOk());

  std::string ct = test::HexDecodeOrDie(test_case.hex_ciphertext);
  absl::StatusOr<absl::Cord> recovered_plaintext = (*aead)->Decrypt(
      absl::Cord(absl::StrCat(test_case.nonce, ct)), absl::Cord(test_case.aad));
  ASSERT_THAT(recovered_plaintext, IsOk());
  ASSERT_THAT(*recovered_plaintext, Eq(absl::Cord(test_case.plaintext)));
}

INSTANTIATE_TEST_SUITE_P(
    XAesGcmTestVectors, XAesGcmTestVectors, testing::ValuesIn(GetTestVectors()),
    [](const testing::TestParamInfo<XAesGcmTestVectors::ParamType>& info) {
      return info.param.name;
    });

TEST(XAesGcmTest, EncryptDecrypt) {
  absl::StatusOr<XAesGcmKey> key = CreateKey(kMinSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<CordAead>> aead =
      NewCordXAesGcmBoringSsl(*key);
  ASSERT_THAT(aead, IsOk());

  absl::Cord pt(Random::GetRandomBytes(4096));
  absl::Cord aad("aad");
  absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(pt, aad);
  ASSERT_THAT(ct, IsOk());
  absl::StatusOr<absl::Cord> recovered_plaintext = (*aead)->Decrypt(*ct, aad);
  ASSERT_THAT(recovered_plaintext, IsOk());
  ASSERT_THAT(*recovered_plaintext, Eq(pt));
}

TEST(XAesGcmTest, DecryptWithInvalidCiphertextSizeFails) {
  absl::StatusOr<XAesGcmKey> key = CreateKey(kMinSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<CordAead>> aead =
      NewCordXAesGcmBoringSsl(*key);
  ASSERT_THAT(aead, IsOk());

  for (int size = 0; size < kCtOverhead + kMinSaltSize; size++) {
    EXPECT_THAT(
        (*aead)
            ->Decrypt(absl::Cord(Random::GetRandomBytes(size)), absl::Cord(""))
            .status(),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr("ciphertext too short")));
  }
}

TEST(XAesGcmTest, DecryptWithInvalidAssociatedDataFails) {
  absl::StatusOr<XAesGcmKey> key = CreateKey(kMinSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<CordAead>> aead =
      NewCordXAesGcmBoringSsl(*key);
  ASSERT_THAT(aead, IsOk());

  absl::Cord pt(Random::GetRandomBytes(4096));
  absl::Cord aad("aad");
  absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(pt, aad);
  ASSERT_THAT(ct, IsOk());

  EXPECT_THAT((*aead)->Decrypt(*ct, absl::Cord("invalid aad")).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(XAesGcmTest, EncryptReturnsDifferentSaltAndIv) {
  absl::StatusOr<XAesGcmKey> key = CreateKey(kMinSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<CordAead>> aead =
      NewCordXAesGcmBoringSsl(*key);
  ASSERT_THAT(aead, IsOk());

  absl::Cord pt("hello world");
  absl::Cord aad("aad");
  absl::StatusOr<absl::Cord> ct_1 = (*aead)->Encrypt(pt, aad);
  ASSERT_THAT(ct_1, IsOk());
  absl::StatusOr<absl::Cord> ct_2 = (*aead)->Encrypt(pt, aad);
  ASSERT_THAT(ct_2, IsOk());

  absl::Cord salt_1 = ct_1->Subcord(0, kMinSaltSize);
  absl::Cord salt_2 = ct_2->Subcord(0, kMinSaltSize);
  EXPECT_THAT(salt_1, Not(Eq(salt_2)));

  absl::Cord iv_1 = ct_1->Subcord(kMinSaltSize, kIvSize);
  absl::Cord iv_2 = ct_2->Subcord(kMinSaltSize, kIvSize);
  EXPECT_THAT(iv_1, Not(Eq(iv_2)));
}

TEST(XAesGcmTest, SaltModificationFailsDecryption) {
  absl::StatusOr<XAesGcmKey> key = CreateKey(kMinSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<CordAead>> aead =
      NewCordXAesGcmBoringSsl(*key);
  ASSERT_THAT(aead, IsOk());

  absl::Cord pt("hello world");
  absl::Cord aad("aad");
  absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(pt, aad);
  ASSERT_THAT(ct, IsOk());

  char s = ct->Subcord(0, 1).Flatten()[0];
  s++;
  ct->RemovePrefix(1);
  ct->Prepend(absl::string_view(&s, 1));

  EXPECT_THAT((*aead)->Decrypt(*ct, aad).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(XAesGcmTest, DifferentSaltSizeFailsDecryption) {
  absl::StatusOr<XAesGcmKey> key = CreateKey(kMinSaltSize);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<CordAead>> encrypter =
      NewCordXAesGcmBoringSsl(*key);
  ASSERT_THAT(encrypter, IsOk());

  absl::Cord pt("hello world");
  absl::Cord aad("aad");
  absl::StatusOr<absl::Cord> ct = (*encrypter)->Encrypt(pt, aad);
  ASSERT_THAT(ct, IsOk());

  absl::StatusOr<XAesGcmKey> other_key = CreateKey(kMaxSaltSize);
  ASSERT_THAT(other_key, IsOk());
  absl::StatusOr<std::unique_ptr<CordAead>> decrypter =
      NewCordXAesGcmBoringSsl(*other_key);
  ASSERT_THAT(decrypter, IsOk());

  EXPECT_THAT((*decrypter)->Decrypt(*ct, aad).status(),
              StatusIs(absl::StatusCode::kInternal));

  decrypter = NewCordXAesGcmBoringSsl(*key);
  ASSERT_THAT(decrypter, IsOk());
  absl::StatusOr<absl::Cord> decrypted = (*decrypter)->Decrypt(*ct, aad);
  EXPECT_THAT(decrypted, IsOk());
  EXPECT_THAT(*decrypted, Eq(pt));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
