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

#include "tink/hybrid/internal/ecies_aead_hkdf_hybrid_decrypt.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "tink/hybrid/ecies_private_key.h"
#include "tink/hybrid/internal/testing/ecies_aead_hkdf_test_vectors.h"
#include "tink/hybrid/internal/testing/hybrid_test_vectors.h"
#include "tink/hybrid_decrypt.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using EciesAeadHkdfHybridDecryptTest = TestWithParam<HybridTestVector>;

INSTANTIATE_TEST_SUITE_P(EciesAeadHkdfHybridDecryptTests,
                         EciesAeadHkdfHybridDecryptTest,
                         ValuesIn(CreateEciesTestVectors()));

TEST_P(EciesAeadHkdfHybridDecryptTest, DecryptTestVectors) {
  const HybridTestVector& test_vector = GetParam();
  const auto* ecies_private_key = dynamic_cast<const EciesPrivateKey*>(
      test_vector.hybrid_private_key.get());
  ASSERT_THAT(ecies_private_key, NotNull());

  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decryptor =
      NewEciesAeadHkdfHybridDecrypt(*ecies_private_key);
  ASSERT_THAT(decryptor, IsOk());

  EXPECT_THAT(
      (*decryptor)->Decrypt(test_vector.ciphertext, test_vector.context_info),
      IsOkAndHolds(Eq(test_vector.plaintext)));
}

TEST_P(EciesAeadHkdfHybridDecryptTest, DecryptModifiedCiphertextFails) {
  const HybridTestVector& test_vector = GetParam();
  const auto* ecies_private_key = dynamic_cast<const EciesPrivateKey*>(
      test_vector.hybrid_private_key.get());
  ASSERT_THAT(ecies_private_key, NotNull());

  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decryptor =
      NewEciesAeadHkdfHybridDecrypt(*ecies_private_key);
  ASSERT_THAT(decryptor, IsOk());

  std::string modified_ciphertext = test_vector.ciphertext;
  modified_ciphertext.back() ^= 1;
  EXPECT_THAT(
      (*decryptor)->Decrypt(modified_ciphertext, test_vector.context_info),
      Not(IsOk()));

  // Truncated ciphertext.
  EXPECT_THAT((*decryptor)
                  ->Decrypt(ecies_private_key->GetOutputPrefix(),
                            test_vector.context_info),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Modified context info.
  EXPECT_THAT((*decryptor)
                  ->Decrypt(test_vector.ciphertext,
                            absl::StrCat(test_vector.context_info, "x")),
              Not(IsOk()));

  // Modified output prefix.
  if (!ecies_private_key->GetOutputPrefix().empty()) {
    std::string wrong_prefix_ciphertext = test_vector.ciphertext;
    wrong_prefix_ciphertext[0] ^= 1;
    EXPECT_THAT(
        (*decryptor)
            ->Decrypt(wrong_prefix_ciphertext, test_vector.context_info),
        StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
