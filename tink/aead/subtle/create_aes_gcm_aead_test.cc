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

#include "tink/aead/subtle/create_aes_gcm_aead.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/aes_gcm_test_vectors.h"
#include "tink/internal/fips_utils.h"
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
using ::testing::StartsWith;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

class CreateAesGcmAeadTestVectorTest : public TestWithParam<AeadTestVector> {
 protected:
  void SetUp() override {
    if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
      GTEST_SKIP() << "Test should not run in FIPS mode when BoringCrypto is "
                      "unavailable.";
    }
  }
};

TEST_P(CreateAesGcmAeadTestVectorTest, DecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const AesGcmKey& key = dynamic_cast<const AesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = CreateAesGcmAead(key);
  ASSERT_THAT(aead, IsOk());

  EXPECT_THAT(
      (*aead)->Decrypt(test_vector.ciphertext, test_vector.associated_data),
      IsOkAndHolds(test_vector.plaintext));
}

TEST_P(CreateAesGcmAeadTestVectorTest, EncryptDecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const AesGcmKey& key = dynamic_cast<const AesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = CreateAesGcmAead(key);
  ASSERT_THAT(aead, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(test_vector.plaintext, test_vector.associated_data);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT(*ciphertext, StartsWith(key.GetOutputPrefix()));

  EXPECT_THAT((*aead)->Decrypt(*ciphertext, test_vector.associated_data),
              IsOkAndHolds(test_vector.plaintext));
}

INSTANTIATE_TEST_SUITE_P(CreateAesGcmAeadTestVectorTests,
                         CreateAesGcmAeadTestVectorTest,
                         ValuesIn(CreateAesGcmTestVectors()));

TEST(CreateAesGcmAeadTest, Rejects24ByteAesKey) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test should not run in FIPS mode when BoringCrypto is "
                    "unavailable.";
  }
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

  EXPECT_THAT(CreateAesGcmAead(*key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAesGcmAeadTest, RejectsInvalidIvSize) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test should not run in FIPS mode when BoringCrypto is "
                    "unavailable.";
  }
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

  EXPECT_THAT(CreateAesGcmAead(*key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAesGcmAeadTest, RejectsInvalidTagSize) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test should not run in FIPS mode when BoringCrypto is "
                    "unavailable.";
  }
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

  EXPECT_THAT(CreateAesGcmAead(*key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAesGcmAeadTest, DecryptFailsWithModifiedCiphertextOrAssociatedData) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test should not run in FIPS mode when BoringCrypto is "
                    "unavailable.";
  }
  const AeadTestVector& test_vector =
      GetAesGcmTestVector(16, AesGcmParameters::Variant::kTink);
  const AesGcmKey& key = dynamic_cast<const AesGcmKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = CreateAesGcmAead(key);
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

TEST(CreateAesGcmAeadTest, FipsModeSucceedsWithBoringCrypto) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test only runs in FIPS-only mode with BoringCrypto.";
  }
  const AeadTestVector& test_vector_128 =
      GetAesGcmTestVector(16, AesGcmParameters::Variant::kTink);
  const AeadTestVector& test_vector_256 =
      GetAesGcmTestVector(32, AesGcmParameters::Variant::kTink);
  const AesGcmKey& key_128 =
      dynamic_cast<const AesGcmKey&>(*test_vector_128.aead_key);
  const AesGcmKey& key_256 =
      dynamic_cast<const AesGcmKey&>(*test_vector_256.aead_key);
  EXPECT_THAT(CreateAesGcmAead(key_128), IsOk());
  EXPECT_THAT(CreateAesGcmAead(key_256), IsOk());
}

TEST(CreateAesGcmAeadTest, FipsModeFailsWithoutBoringCrypto) {
  if (!internal::IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test only runs in FIPS-only mode without BoringCrypto.";
  }
  const AeadTestVector& test_vector_128 =
      GetAesGcmTestVector(16, AesGcmParameters::Variant::kTink);
  const AeadTestVector& test_vector_256 =
      GetAesGcmTestVector(32, AesGcmParameters::Variant::kTink);
  const AesGcmKey& key_128 =
      dynamic_cast<const AesGcmKey&>(*test_vector_128.aead_key);
  const AesGcmKey& key_256 =
      dynamic_cast<const AesGcmKey&>(*test_vector_256.aead_key);
  EXPECT_THAT(CreateAesGcmAead(key_128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(CreateAesGcmAead(key_256).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
