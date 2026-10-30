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

#include "tink/daead/internal/aes_siv_boringssl.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/daead/aes_siv_key.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/daead/internal/aes_siv_test_vectors.h"
#include "tink/deterministic_aead.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/testing/wycheproof_util.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::wycheproof_testing::GetBytesFromHexValue;
using ::crypto::tink::internal::wycheproof_testing::ReadTestVectorsV1;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using AesSivBoringSslTestWithVectors = TestWithParam<AesSivTestVector>;

INSTANTIATE_TEST_SUITE_P(AesSivBoringSslTestWithVectors,
                         AesSivBoringSslTestWithVectors,
                         ValuesIn(CreateAesSivTestVectors()));

TEST_P(AesSivBoringSslTestWithVectors, EncryptAndDecrypt) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const AesSivTestVector& test_vector = GetParam();
  if (test_vector.key.GetParameters().KeySizeInBytes() != 64) {
    EXPECT_THAT(NewAesSivBoringSsl(test_vector.key),
                StatusIs(absl::StatusCode::kInvalidArgument));
    return;
  }

  absl::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      NewAesSivBoringSsl(test_vector.key);
  ASSERT_THAT(daead, IsOk());

  EXPECT_THAT((*daead)->EncryptDeterministically(test_vector.plaintext,
                                                 test_vector.aad),
              IsOkAndHolds(test_vector.ciphertext));
  EXPECT_THAT((*daead)->DecryptDeterministically(test_vector.ciphertext,
                                                 test_vector.aad),
              IsOkAndHolds(test_vector.plaintext));
}

TEST_P(AesSivBoringSslTestWithVectors, DecryptFailsWithModifiedCiphertext) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const AesSivTestVector& test_vector = GetParam();
  if (test_vector.key.GetParameters().KeySizeInBytes() != 64) {
    return;
  }

  absl::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      NewAesSivBoringSsl(test_vector.key);
  ASSERT_THAT(daead, IsOk());

  for (size_t i = 0; i < test_vector.ciphertext.size(); ++i) {
    std::string modified_ciphertext = test_vector.ciphertext;
    modified_ciphertext[i] ^= 1;
    EXPECT_THAT((*daead)->DecryptDeterministically(modified_ciphertext,
                                                   test_vector.aad),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST_P(AesSivBoringSslTestWithVectors, DecryptFailsWithWrongAssociatedData) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const AesSivTestVector& test_vector = GetParam();
  if (test_vector.key.GetParameters().KeySizeInBytes() != 64) {
    return;
  }

  absl::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      NewAesSivBoringSsl(test_vector.key);
  ASSERT_THAT(daead, IsOk());

  EXPECT_THAT(
      (*daead)->DecryptDeterministically(test_vector.ciphertext, "wrong_aad"),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesSivBoringSslTestWithVectors, DecryptFailsIfCiphertextTooShort) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const AesSivTestVector& test_vector = GetParam();
  if (test_vector.key.GetParameters().KeySizeInBytes() != 64) {
    return;
  }

  absl::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      NewAesSivBoringSsl(test_vector.key);
  ASSERT_THAT(daead, IsOk());

  size_t min_ciphertext_size = test_vector.key.GetOutputPrefix().size() + 16;
  for (size_t len = 0; len < min_ciphertext_size; ++len) {
    EXPECT_THAT((*daead)->DecryptDeterministically(
                    absl::string_view(test_vector.ciphertext).substr(0, len),
                    test_vector.aad),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(AesSivBoringSslTest, DecryptWithWrongPrefixFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const AesSivTestVector& test_vector =
      GetAesSivTestVector(64, AesSivParameters::Variant::kTink);
  absl::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      NewAesSivBoringSsl(test_vector.key);
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

TEST(AesSivBoringSslTest, NullPtrStringView) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const AesSivTestVector& test_vector =
      GetAesSivTestVector(64, AesSivParameters::Variant::kNoPrefix);
  absl::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      NewAesSivBoringSsl(test_vector.key);
  ASSERT_THAT(daead, IsOk());

  absl::string_view null_view;
  absl::StatusOr<std::string> ct =
      (*daead)->EncryptDeterministically(null_view, null_view);
  ASSERT_THAT(ct, IsOk());
  EXPECT_THAT((*daead)->DecryptDeterministically(*ct, null_view),
              IsOkAndHolds(""));
  EXPECT_THAT((*daead)->DecryptDeterministically(null_view, ""), Not(IsOk()));

  std::string message("123456789abcdefghijklmnop");
  ct = (*daead)->EncryptDeterministically(message, null_view);
  ASSERT_THAT(ct, IsOk());
  EXPECT_THAT((*daead)->DecryptDeterministically(*ct, ""),
              IsOkAndHolds(message));

  ct = (*daead)->EncryptDeterministically(message, "");
  ASSERT_THAT(ct, IsOk());
  EXPECT_THAT((*daead)->DecryptDeterministically(*ct, null_view),
              IsOkAndHolds(message));
}

TEST(AesSivBoringSslTest, EncryptDecryptVariousMessageSizes) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const AesSivTestVector& test_vector =
      GetAesSivTestVector(64, AesSivParameters::Variant::kTink);
  absl::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      NewAesSivBoringSsl(test_vector.key);
  ASSERT_THAT(daead, IsOk());

  std::string associated_data = "Associated data";
  for (int i = 0; i < 256; ++i) {
    std::string message(i, 'a');
    absl::StatusOr<std::string> ct =
        (*daead)->EncryptDeterministically(message, associated_data);
    ASSERT_THAT(ct, IsOk());
    EXPECT_THAT((*daead)->DecryptDeterministically(*ct, associated_data),
                IsOkAndHolds(message));
  }
}

TEST(AesSivBoringSslTest, WycheproofTestVectors) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  absl::StatusOr<google::protobuf::Struct> parsed_input =
      ReadTestVectorsV1("aes_siv_cmac_test.json");
  ASSERT_THAT(parsed_input, IsOk());

  absl::StatusOr<AesSivParameters> params =
      AesSivParameters::Create(64, AesSivParameters::Variant::kNoPrefix);
  ASSERT_THAT(params, IsOk());

  int skipped_test_groups = 0;
  const google::protobuf::Value& test_groups =
      parsed_input->fields().at("testGroups");
  for (const google::protobuf::Value& test_group :
       test_groups.list_value().values()) {
    const auto& test_group_fields = test_group.struct_value().fields();
    const size_t key_size = test_group_fields.at("keySize").number_value();
    if (key_size / 8 != 64) {
      skipped_test_groups++;
      continue;
    }
    for (const google::protobuf::Value& test :
         test_group.struct_value().fields().at("tests").list_value().values()) {
      auto test_fields = test.struct_value().fields();
      std::string comment = test_fields.at("comment").string_value();
      std::string key_bytes = GetBytesFromHexValue(test_fields.at("key"));
      std::string msg = GetBytesFromHexValue(test_fields.at("msg"));
      std::string ct = GetBytesFromHexValue(test_fields.at("ct"));
      std::string associated_data = GetBytesFromHexValue(test_fields.at("aad"));
      int id = static_cast<int>(test_fields.at("tcId").number_value());
      std::string result = test_fields.at("result").string_value();

      absl::StatusOr<AesSivKey> key = AesSivKey::Create(
          *params, RestrictedData(key_bytes, InsecureSecretKeyAccess::Get()),
          /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
      ASSERT_THAT(key, IsOk());
      absl::StatusOr<std::unique_ptr<DeterministicAead>> cipher =
          NewAesSivBoringSsl(*key);
      ASSERT_THAT(cipher, IsOk());

      absl::StatusOr<std::string> encrypted =
          (*cipher)->EncryptDeterministically(msg, associated_data);
      ASSERT_THAT(encrypted, IsOk());
      if (result == "valid" || result == "acceptable") {
        EXPECT_EQ(test::HexEncode(ct), test::HexEncode(*encrypted))
            << "incorrect encryption: " << id << " " << comment;
      } else {
        EXPECT_NE(test::HexEncode(ct), test::HexEncode(*encrypted))
            << "invalid encryption: " << id << " " << comment;
      }

      absl::StatusOr<std::string> decrypted =
          (*cipher)->DecryptDeterministically(ct, associated_data);
      if (decrypted.ok()) {
        if (result == "invalid") {
          ADD_FAILURE() << "decrypted invalid ciphertext:" << id;
        } else {
          EXPECT_EQ(test::HexEncode(msg), test::HexEncode(*decrypted))
              << "incorrect decryption: " << id << " " << comment;
        }
      } else {
        EXPECT_NE(result, "valid")
            << "failed to decrypt: " << id << " " << comment;
      }
    }
  }
  EXPECT_EQ(skipped_test_groups, 2);
}

TEST(AesSivBoringSslTest, FipsOnly) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }
  const AesSivTestVector& test_vector =
      GetAesSivTestVector(64, AesSivParameters::Variant::kNoPrefix);
  EXPECT_THAT(NewAesSivBoringSsl(test_vector.key),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
