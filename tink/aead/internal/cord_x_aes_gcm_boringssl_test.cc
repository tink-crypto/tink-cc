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

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/x_aes_gcm_test_vectors.h"
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/aead/x_aes_gcm_parameters.h"
#include "tink/subtle/random.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::subtle::Random;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

constexpr int kMinSaltSize = 8;
constexpr int kMaxSaltSize = 12;
constexpr int kIvSize = 12;
constexpr int kCtOverhead = kIvSize + 16;

std::vector<AeadTestVector> GetNoPrefixTestVectors() {
  std::vector<AeadTestVector> vectors;
  for (int salt_size = kMinSaltSize; salt_size <= kMaxSaltSize; ++salt_size) {
    vectors.push_back(
        GetXAesGcmTestVector(salt_size, XAesGcmParameters::Variant::kNoPrefix));
  }
  return vectors;
}

using XAesGcmTestVectors = TestWithParam<AeadTestVector>;

TEST_P(XAesGcmTestVectors, DecryptKnownTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const XAesGcmKey& key =
      dynamic_cast<const XAesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<CordAead>> aead = NewCordXAesGcmBoringSsl(key);
  ASSERT_THAT(aead, IsOk());

  EXPECT_THAT((*aead)->Decrypt(absl::Cord(test_vector.ciphertext),
                               absl::Cord(test_vector.associated_data)),
              IsOkAndHolds(absl::Cord(test_vector.plaintext)));
}

TEST_P(XAesGcmTestVectors, EncryptDecrypt) {
  const AeadTestVector& test_vector = GetParam();
  const XAesGcmKey& key =
      dynamic_cast<const XAesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<CordAead>> aead = NewCordXAesGcmBoringSsl(key);
  ASSERT_THAT(aead, IsOk());

  absl::Cord pt(Random::GetRandomBytes(4096));
  absl::Cord aad("aad");
  absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(pt, aad);
  ASSERT_THAT(ct, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ct, aad), IsOkAndHolds(pt));
}

TEST_P(XAesGcmTestVectors, DecryptWithInvalidCiphertextSizeFails) {
  const AeadTestVector& test_vector = GetParam();
  const XAesGcmKey& key =
      dynamic_cast<const XAesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<CordAead>> aead = NewCordXAesGcmBoringSsl(key);
  ASSERT_THAT(aead, IsOk());

  const size_t min_size = key.GetParameters().SaltSizeBytes() + kCtOverhead;
  for (size_t size = 0; size < min_size; size++) {
    EXPECT_THAT(
        (*aead)
            ->Decrypt(absl::Cord(Random::GetRandomBytes(size)), absl::Cord(""))
            .status(),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr("ciphertext too short")));
  }
}

TEST_P(XAesGcmTestVectors, DecryptWithInvalidAssociatedDataFails) {
  const AeadTestVector& test_vector = GetParam();
  const XAesGcmKey& key =
      dynamic_cast<const XAesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<CordAead>> aead = NewCordXAesGcmBoringSsl(key);
  ASSERT_THAT(aead, IsOk());

  EXPECT_THAT((*aead)
                  ->Decrypt(absl::Cord(test_vector.ciphertext),
                            absl::Cord("invalid aad"))
                  .status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST_P(XAesGcmTestVectors, EncryptReturnsDifferentSaltAndIv) {
  const AeadTestVector& test_vector = GetParam();
  const XAesGcmKey& key =
      dynamic_cast<const XAesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<CordAead>> aead = NewCordXAesGcmBoringSsl(key);
  ASSERT_THAT(aead, IsOk());

  absl::Cord pt("hello world");
  absl::Cord aad("aad");
  absl::StatusOr<absl::Cord> ct_1 = (*aead)->Encrypt(pt, aad);
  ASSERT_THAT(ct_1, IsOk());
  absl::StatusOr<absl::Cord> ct_2 = (*aead)->Encrypt(pt, aad);
  ASSERT_THAT(ct_2, IsOk());

  const int salt_size = key.GetParameters().SaltSizeBytes();
  absl::Cord salt_1 = ct_1->Subcord(0, salt_size);
  absl::Cord salt_2 = ct_2->Subcord(0, salt_size);
  EXPECT_THAT(salt_1, Not(Eq(salt_2)));

  absl::Cord iv_1 = ct_1->Subcord(salt_size, kIvSize);
  absl::Cord iv_2 = ct_2->Subcord(salt_size, kIvSize);
  EXPECT_THAT(iv_1, Not(Eq(iv_2)));
}

TEST_P(XAesGcmTestVectors, SaltModificationFailsDecryption) {
  const AeadTestVector& test_vector = GetParam();
  const XAesGcmKey& key =
      dynamic_cast<const XAesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<CordAead>> aead = NewCordXAesGcmBoringSsl(key);
  ASSERT_THAT(aead, IsOk());

  std::string modified_ct = test_vector.ciphertext;
  modified_ct[0] ^= 0x01;
  EXPECT_THAT((*aead)
                  ->Decrypt(absl::Cord(modified_ct),
                            absl::Cord(test_vector.associated_data))
                  .status(),
              StatusIs(absl::StatusCode::kInternal));
}

INSTANTIATE_TEST_SUITE_P(XAesGcmTestVectors, XAesGcmTestVectors,
                         ValuesIn(GetNoPrefixTestVectors()));

TEST(XAesGcmTest, DifferentSaltSizeFailsDecryption) {
  const AeadTestVector& min_salt_vector =
      GetXAesGcmTestVector(kMinSaltSize, XAesGcmParameters::Variant::kNoPrefix);
  const XAesGcmKey& key =
      dynamic_cast<const XAesGcmKey&>(*min_salt_vector.aead_key);
  absl::StatusOr<std::unique_ptr<CordAead>> encrypter =
      NewCordXAesGcmBoringSsl(key);
  ASSERT_THAT(encrypter, IsOk());

  absl::Cord pt("hello world");
  absl::Cord aad("aad");
  absl::StatusOr<absl::Cord> ct = (*encrypter)->Encrypt(pt, aad);
  ASSERT_THAT(ct, IsOk());

  const AeadTestVector& max_salt_vector =
      GetXAesGcmTestVector(kMaxSaltSize, XAesGcmParameters::Variant::kNoPrefix);
  const XAesGcmKey& other_key =
      dynamic_cast<const XAesGcmKey&>(*max_salt_vector.aead_key);
  absl::StatusOr<std::unique_ptr<CordAead>> decrypter =
      NewCordXAesGcmBoringSsl(other_key);
  ASSERT_THAT(decrypter, IsOk());

  EXPECT_THAT((*decrypter)->Decrypt(*ct, aad).status(),
              StatusIs(absl::StatusCode::kInternal));

  decrypter = NewCordXAesGcmBoringSsl(key);
  ASSERT_THAT(decrypter, IsOk());
  absl::StatusOr<absl::Cord> decrypted = (*decrypter)->Decrypt(*ct, aad);
  EXPECT_THAT(decrypted, IsOk());
  EXPECT_THAT(*decrypted, Eq(pt));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
