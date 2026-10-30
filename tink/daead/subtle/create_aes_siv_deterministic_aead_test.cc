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

#include "tink/daead/subtle/create_aes_siv_deterministic_aead.h"

#include <cstddef>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/daead/internal/aes_siv_test_vectors.h"
#include "tink/deterministic_aead.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::AesSivTestVector;
using ::crypto::tink::internal::CreateAesSivTestVectors;
using ::crypto::tink::internal::GetAesSivTestVector;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using CreateAesSivDeterministicAeadTest = TestWithParam<AesSivTestVector>;

INSTANTIATE_TEST_SUITE_P(CreateAesSivDeterministicAeadTest,
                         CreateAesSivDeterministicAeadTest,
                         ValuesIn(CreateAesSivTestVectors()));

TEST_P(CreateAesSivDeterministicAeadTest, EncryptAndDecrypt) {
  const AesSivTestVector& test_vector = GetParam();
  if (test_vector.key.GetParameters().KeySizeInBytes() != 64) {
    EXPECT_THAT(CreateAesSivDeterministicAead(test_vector.key),
                StatusIs(absl::StatusCode::kInvalidArgument));
    return;
  }

  absl::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      CreateAesSivDeterministicAead(test_vector.key);
  ASSERT_THAT(daead, IsOk());

  EXPECT_THAT((*daead)->EncryptDeterministically(test_vector.plaintext,
                                                 test_vector.aad),
              IsOkAndHolds(test_vector.ciphertext));
  EXPECT_THAT((*daead)->DecryptDeterministically(test_vector.ciphertext,
                                                 test_vector.aad),
              IsOkAndHolds(test_vector.plaintext));
}

TEST_P(CreateAesSivDeterministicAeadTest, DecryptFailsWithModifiedCiphertext) {
  const AesSivTestVector& test_vector = GetParam();
  if (test_vector.key.GetParameters().KeySizeInBytes() != 64) {
    return;
  }

  absl::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      CreateAesSivDeterministicAead(test_vector.key);
  ASSERT_THAT(daead, IsOk());

  for (size_t i = 0; i < test_vector.ciphertext.size(); ++i) {
    std::string modified_ciphertext = test_vector.ciphertext;
    modified_ciphertext[i] ^= 1;
    EXPECT_THAT((*daead)->DecryptDeterministically(modified_ciphertext,
                                                   test_vector.aad),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST_P(CreateAesSivDeterministicAeadTest, DecryptFailsWithWrongAssociatedData) {
  const AesSivTestVector& test_vector = GetParam();
  if (test_vector.key.GetParameters().KeySizeInBytes() != 64) {
    return;
  }

  absl::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      CreateAesSivDeterministicAead(test_vector.key);
  ASSERT_THAT(daead, IsOk());

  EXPECT_THAT(
      (*daead)->DecryptDeterministically(test_vector.ciphertext, "wrong_aad"),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAesSivDeterministicAeadTest, DecryptWithWrongPrefixFails) {
  const AesSivTestVector& test_vector =
      GetAesSivTestVector(64, AesSivParameters::Variant::kTink);
  absl::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      CreateAesSivDeterministicAead(test_vector.key);
  ASSERT_THAT(daead, IsOk());

  ASSERT_TRUE(absl::StartsWith(test_vector.ciphertext,
                               test_vector.key.GetOutputPrefix()));
  std::string wrong_prefix_ciphertext =
      absl::StrCat("\x01\x99\x99\x99\x99",
                   absl::string_view(test_vector.ciphertext)
                       .substr(test_vector.key.GetOutputPrefix().size()));
  EXPECT_THAT((*daead)->DecryptDeterministically(wrong_prefix_ciphertext,
                                                 test_vector.aad),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
