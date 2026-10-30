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

#include "tink/hybrid/subtle/create_hpke_decrypt.h"

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
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid/internal/testing/hpke_test_vectors.h"
#include "tink/hybrid/internal/testing/hybrid_test_vectors.h"
#include "tink/hybrid_decrypt.h"
#include "tink/internal/testing/ec_test_vectors.h"
#include "tink/partial_key_access.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::CreateHpkeTestVectors;
using ::crypto::tink::internal::GetHpkeNistCurveTestCase;
using ::crypto::tink::internal::GetHpkeTestVector;
using ::crypto::tink::internal::HybridTestVector;
using ::crypto::tink::internal::P256PointAsString;
using ::crypto::tink::internal::P256SecretValue;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using CreateHpkeDecryptTestVectorTest = TestWithParam<HybridTestVector>;

TEST_P(CreateHpkeDecryptTestVectorTest, DecryptTestVectors) {
  const HybridTestVector& test_vector = GetParam();
  const HpkePrivateKey& key =
      dynamic_cast<const HpkePrivateKey&>(*test_vector.hybrid_private_key);
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypter =
      CreateHpkeDecrypt(key);
  ASSERT_THAT(decrypter, IsOk());

  EXPECT_THAT(
      (*decrypter)->Decrypt(test_vector.ciphertext, test_vector.context_info),
      IsOkAndHolds(test_vector.plaintext));
}

INSTANTIATE_TEST_SUITE_P(CreateHpkeDecryptTestVectorTests,
                         CreateHpkeDecryptTestVectorTest,
                         ValuesIn(CreateHpkeTestVectors()));

TEST(CreateHpkeDecryptTest, DecryptFailsWithModifiedCiphertextOrContextInfo) {
  const HybridTestVector& test_vector = GetHpkeTestVector(
      HpkeParameters::KemId::kDhkemP256HkdfSha256,
      HpkeParameters::KdfId::kHkdfSha256, HpkeParameters::AeadId::kAesGcm128,
      HpkeParameters::Variant::kTink);
  const HpkePrivateKey& key =
      dynamic_cast<const HpkePrivateKey&>(*test_vector.hybrid_private_key);
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypter =
      CreateHpkeDecrypt(key);
  ASSERT_THAT(decrypter, IsOk());

  for (size_t i = 0; i < test_vector.ciphertext.size(); ++i) {
    std::string modified_ciphertext = test_vector.ciphertext;
    modified_ciphertext[i] ^= 0x01;
    EXPECT_THAT((*decrypter)
                    ->Decrypt(modified_ciphertext, test_vector.context_info)
                    .status(),
                Not(IsOk()));
  }

  EXPECT_THAT((*decrypter)
                  ->Decrypt(test_vector.ciphertext, "modified context info")
                  .status(),
              Not(IsOk()));

  for (size_t len = 0; len < test_vector.ciphertext.size(); ++len) {
    EXPECT_THAT(
        (*decrypter)
            ->Decrypt(absl::string_view(test_vector.ciphertext).substr(0, len),
                      test_vector.context_info)
            .status(),
        Not(IsOk()));
  }
}

TEST(CreateHpkeDecryptTest, P384Fails) {
  EXPECT_THAT(CreateHpkeDecrypt(*GetHpkeNistCurveTestCase(
                                     subtle::EllipticCurveType::NIST_P384)
                                     .private_key)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateHpkeDecryptTest, P521Fails) {
  EXPECT_THAT(CreateHpkeDecrypt(*GetHpkeNistCurveTestCase(
                                     subtle::EllipticCurveType::NIST_P521)
                                     .private_key)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateHpkeDecryptTest, Sha384Fails) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha384)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(CreateHpkeDecrypt(*private_key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateHpkeDecryptTest, Sha512Fails) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha512)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(CreateHpkeDecrypt(*private_key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
