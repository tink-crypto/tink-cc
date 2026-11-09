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

#include "tink/hybrid/subtle/create_ecies_encrypt.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_private_key.h"
#include "tink/hybrid/ecies_public_key.h"
#include "tink/hybrid/internal/testing/ecies_aead_hkdf_test_vectors.h"
#include "tink/hybrid/internal/testing/hybrid_test_vectors.h"
#include "tink/hybrid/subtle/create_ecies_decrypt.h"
#include "tink/hybrid/subtle/create_ecies_key.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/partial_key_access.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::CreateEciesTestVectors;
using ::crypto::tink::internal::HybridTestVector;
using ::testing::NotNull;
using ::testing::StartsWith;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using CreateEciesHybridEncryptTestWithVectors = TestWithParam<HybridTestVector>;

INSTANTIATE_TEST_SUITE_P(CreateEciesHybridEncryptTests,
                         CreateEciesHybridEncryptTestWithVectors,
                         ValuesIn(CreateEciesTestVectors()));

TEST_P(CreateEciesHybridEncryptTestWithVectors, EncryptAndDecryptWorks) {
  const HybridTestVector& test_vector = GetParam();
  const auto* ecies_private_key = dynamic_cast<const EciesPrivateKey*>(
      test_vector.hybrid_private_key.get());
  ASSERT_THAT(ecies_private_key, NotNull());

  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypter =
      CreateEciesHybridEncrypt(ecies_private_key->GetPublicKey());
  ASSERT_THAT(encrypter, IsOk());

  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypter =
      CreateEciesHybridDecrypt(*ecies_private_key);
  ASSERT_THAT(decrypter, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*encrypter)->Encrypt(test_vector.plaintext, test_vector.context_info);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT(*ciphertext,
              StartsWith(ecies_private_key->GetPublicKey().GetOutputPrefix()));

  EXPECT_THAT((*decrypter)->Decrypt(*ciphertext, test_vector.context_info),
              IsOkAndHolds(test_vector.plaintext));
}

TEST(CreateEciesHybridEncryptTest, EncryptAndDecryptGeneratedKeyWorks) {
  absl::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<EciesPrivateKey> private_key =
      CreateEciesPrivateKey(*parameters, /*id_requirement=*/0x11223344);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypter =
      CreateEciesHybridEncrypt(private_key->GetPublicKey());
  ASSERT_THAT(encrypter, IsOk());

  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypter =
      CreateEciesHybridDecrypt(*private_key);
  ASSERT_THAT(decrypter, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*encrypter)->Encrypt("some plaintext", "some context info");
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*decrypter)->Decrypt(*ciphertext, "some context info"),
              IsOkAndHolds("some plaintext"));
}

TEST(CreateEciesHybridEncryptTest, EncryptWithBadX25519PublicKeyFails) {
  absl::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<EciesPublicKey> bad_public_key =
      EciesPublicKey::CreateForCurveX25519(*parameters, std::string(32, '\0'),
                                           /*id_requirement=*/std::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(bad_public_key, IsOk());

  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypter =
      CreateEciesHybridEncrypt(*bad_public_key);
  ASSERT_THAT(encrypter, IsOk());

  EXPECT_THAT((*encrypter)->Encrypt("plaintext", "context"),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
