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

#include "tink/aead/subtle/create_aes_eax_aead.h"

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
#include "tink/aead/aes_eax_key.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/aes_eax_test_vectors.h"
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
using ::crypto::tink::internal::CreateAesEaxTestVectors;
using ::crypto::tink::internal::GetAesEaxTestVector;
using ::testing::HasSubstr;
using ::testing::StartsWith;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using CreateAesEaxAeadTestVectorTest = TestWithParam<AeadTestVector>;

TEST_P(CreateAesEaxAeadTestVectorTest, DecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = CreateAesEaxAead(key);
  if (key.GetParameters().GetKeySizeInBytes() == 24) {
    EXPECT_THAT(aead.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                        HasSubstr("Invalid key size")));
    return;
  }
  ASSERT_THAT(aead, IsOk());

  EXPECT_THAT(
      (*aead)->Decrypt(test_vector.ciphertext, test_vector.associated_data),
      IsOkAndHolds(test_vector.plaintext));
}

TEST_P(CreateAesEaxAeadTestVectorTest, EncryptDecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = CreateAesEaxAead(key);
  if (key.GetParameters().GetKeySizeInBytes() == 24) {
    EXPECT_THAT(aead.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                        HasSubstr("Invalid key size")));
    return;
  }
  ASSERT_THAT(aead, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(test_vector.plaintext, test_vector.associated_data);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT(*ciphertext, StartsWith(key.GetOutputPrefix()));

  EXPECT_THAT((*aead)->Decrypt(*ciphertext, test_vector.associated_data),
              IsOkAndHolds(test_vector.plaintext));
}

INSTANTIATE_TEST_SUITE_P(CreateAesEaxAeadTestVectorTests,
                         CreateAesEaxAeadTestVectorTest,
                         ValuesIn(CreateAesEaxTestVectors()));

TEST(CreateAesEaxAeadTest, Rejects24ByteAesKey) {
  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(24)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<AesEaxKey> key =
      AesEaxKey::Create(*parameters, RestrictedData(24),
                        /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(CreateAesEaxAead(*key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid key size")));
}

TEST(CreateAesEaxAeadTest, DecryptFailsWithModifiedCiphertextOrAssociatedData) {
  const AeadTestVector& test_vector =
      GetAesEaxTestVector(16, AesEaxParameters::Variant::kTink);
  const AesEaxKey& key = dynamic_cast<const AesEaxKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<Aead>> aead = CreateAesEaxAead(key);
  ASSERT_THAT(aead, IsOk());

  const size_t prefix_size = key.GetOutputPrefix().size();
  const size_t min_ciphertext_size =
      prefix_size + key.GetParameters().GetIvSizeInBytes() +
      key.GetParameters().GetTagSizeInBytes();

  for (size_t i = 0; i < test_vector.ciphertext.size(); ++i) {
    std::string modified_ciphertext = test_vector.ciphertext;
    modified_ciphertext[i] ^= 0x01;
    EXPECT_THAT((*aead)
                    ->Decrypt(modified_ciphertext, test_vector.associated_data)
                    .status(),
                StatusIs(absl::StatusCode::kInvalidArgument,
                         HasSubstr(i < prefix_size ? "Prefix mismatch"
                                                   : "Authentication failed")));
  }

  EXPECT_THAT((*aead)
                  ->Decrypt(test_vector.ciphertext, "modified associated data")
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Authentication failed")));

  for (size_t len = 0; len < test_vector.ciphertext.size(); ++len) {
    EXPECT_THAT(
        (*aead)
            ->Decrypt(absl::string_view(test_vector.ciphertext).substr(0, len),
                      test_vector.associated_data)
            .status(),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr(len < min_ciphertext_size
                               ? "Ciphertext too short"
                               : "Authentication failed")));
  }
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
