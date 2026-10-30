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
////////////////////////////////////////////////////////////////////////////////

#include "tink/aead/subtle/create_aes_gcm_cord_aead.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "absl/strings/string_view.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/aes_gcm_test_vectors.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::AeadTestVector;
using ::crypto::tink::internal::CreateAesGcmTestVectors;
using ::crypto::tink::internal::GetAesGcmTestVector;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using CreateAesGcmCordAeadTestVectorTest = TestWithParam<AeadTestVector>;

TEST_P(CreateAesGcmCordAeadTestVectorTest, DecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const AesGcmKey& key = dynamic_cast<const AesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<CordAead>> aead = CreateAesGcmCordAead(key);
  ASSERT_THAT(aead, IsOk());

  EXPECT_THAT((*aead)->Decrypt(absl::Cord(test_vector.ciphertext),
                               absl::Cord(test_vector.associated_data)),
              IsOkAndHolds(absl::Cord(test_vector.plaintext)));
}

TEST_P(CreateAesGcmCordAeadTestVectorTest, EncryptDecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const AesGcmKey& key = dynamic_cast<const AesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<CordAead>> aead = CreateAesGcmCordAead(key);
  ASSERT_THAT(aead, IsOk());

  absl::Cord plaintext(test_vector.plaintext);
  absl::Cord associated_data(test_vector.associated_data);
  absl::StatusOr<absl::Cord> ciphertext =
      (*aead)->Encrypt(plaintext, associated_data);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_TRUE(ciphertext->StartsWith(key.GetOutputPrefix()));

  EXPECT_THAT((*aead)->Decrypt(*ciphertext, associated_data),
              IsOkAndHolds(plaintext));
}

INSTANTIATE_TEST_SUITE_P(CreateAesGcmCordAeadTestVectorTests,
                         CreateAesGcmCordAeadTestVectorTest,
                         ValuesIn(CreateAesGcmTestVectors()));

TEST(CreateAesGcmCordAeadTest, InvalidIvSizeFails) {
  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *parameters,
      RestrictedData(std::string(16, 'k'), InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(CreateAesGcmCordAead(*key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAesGcmCordAeadTest, InvalidTagSizeFails) {
  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(12)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *parameters,
      RestrictedData(std::string(16, 'k'), InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(CreateAesGcmCordAead(*key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAesGcmCordAeadTest, InvalidKeySizeFails) {
  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(24)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *parameters,
      RestrictedData(std::string(24, 'k'), InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(CreateAesGcmCordAead(*key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAesGcmCordAeadTest,
     DecryptFailsWithModifiedCiphertextOrAssociatedData) {
  const AeadTestVector& test_vector =
      GetAesGcmTestVector(16, AesGcmParameters::Variant::kTink);
  const AesGcmKey& key = dynamic_cast<const AesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<CordAead>> aead = CreateAesGcmCordAead(key);
  ASSERT_THAT(aead, IsOk());
  absl::Cord associated_data(test_vector.associated_data);

  for (size_t i = 0; i < test_vector.ciphertext.size(); ++i) {
    std::string modified_ciphertext = test_vector.ciphertext;
    modified_ciphertext[i] ^= 0x01;
    EXPECT_THAT((*aead)
                    ->Decrypt(absl::Cord(modified_ciphertext), associated_data)
                    .status(),
                Not(IsOk()));
  }

  EXPECT_THAT((*aead)
                  ->Decrypt(absl::Cord(test_vector.ciphertext),
                            absl::Cord("modified associated data"))
                  .status(),
              Not(IsOk()));

  for (size_t len = 0; len < test_vector.ciphertext.size(); ++len) {
    EXPECT_THAT(
        (*aead)
            ->Decrypt(
                absl::Cord(
                    absl::string_view(test_vector.ciphertext).substr(0, len)),
                associated_data)
            .status(),
        Not(IsOk()));
  }
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
