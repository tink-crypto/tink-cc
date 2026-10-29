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

#include "tink/aead/subtle/create_chacha20_poly1305_aead.h"

#include <cstddef>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/chacha20_poly1305_key.h"
#include "tink/aead/chacha20_poly1305_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/chacha20_poly1305_test_vectors.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::crypto::tink::internal::AeadTestVector;
using ::crypto::tink::internal::CreateChaCha20Poly1305TestVectors;
using ::crypto::tink::internal::GetChaCha20Poly1305TestVector;
using ::testing::Not;
using ::testing::StartsWith;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using CreateChaCha20Poly1305AeadTestVectorTest = TestWithParam<AeadTestVector>;

TEST_P(CreateChaCha20Poly1305AeadTestVectorTest, DecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const ChaCha20Poly1305Key& key =
      dynamic_cast<const ChaCha20Poly1305Key&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = CreateChaCha20Poly1305Aead(key);
  ASSERT_THAT(aead, IsOk());

  EXPECT_THAT(
      (*aead)->Decrypt(test_vector.ciphertext, test_vector.associated_data),
      IsOkAndHolds(test_vector.plaintext));
}

TEST_P(CreateChaCha20Poly1305AeadTestVectorTest, EncryptDecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const ChaCha20Poly1305Key& key =
      dynamic_cast<const ChaCha20Poly1305Key&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = CreateChaCha20Poly1305Aead(key);
  ASSERT_THAT(aead, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(test_vector.plaintext, test_vector.associated_data);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT(*ciphertext, StartsWith(key.GetOutputPrefix()));

  EXPECT_THAT((*aead)->Decrypt(*ciphertext, test_vector.associated_data),
              IsOkAndHolds(test_vector.plaintext));
}

INSTANTIATE_TEST_SUITE_P(CreateChaCha20Poly1305AeadTestVectorTests,
                         CreateChaCha20Poly1305AeadTestVectorTest,
                         ValuesIn(CreateChaCha20Poly1305TestVectors()));

TEST(CreateChaCha20Poly1305AeadTest,
     DecryptFailsWithModifiedCiphertextOrAssociatedData) {
  const AeadTestVector& test_vector =
      GetChaCha20Poly1305TestVector(ChaCha20Poly1305Parameters::Variant::kTink);
  const ChaCha20Poly1305Key& key =
      dynamic_cast<const ChaCha20Poly1305Key&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = CreateChaCha20Poly1305Aead(key);
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

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
