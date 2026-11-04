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
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "tink/daead/aes_siv_key.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/daead/internal/aes_siv_test_vectors.h"
#include "tink/daead/subtle/deterministic_aeads.h"
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
using ::crypto::tink::subtle::DeterministicAeads;
using ::testing::Ne;
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
  if (test_vector.key.GetParameters().KeySizeInBytes() == 48) {
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
  if (test_vector.key.GetParameters().KeySizeInBytes() == 48) {
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
  if (test_vector.key.GetParameters().KeySizeInBytes() == 48) {
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
  if (test_vector.key.GetParameters().KeySizeInBytes() == 48) {
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

  int skipped_test_groups = 0;
  const google::protobuf::Value& test_groups =
      parsed_input->fields().at("testGroups");
  for (const google::protobuf::Value& test_group :
       test_groups.list_value().values()) {
    const auto& test_group_fields = test_group.struct_value().fields();
    const size_t key_size = test_group_fields.at("keySize").number_value();
    const size_t key_size_in_bytes = key_size / 8;
    if (key_size_in_bytes != 32 && key_size_in_bytes != 64) {
      skipped_test_groups++;
      continue;
    }
    absl::StatusOr<AesSivParameters> params = AesSivParameters::Create(
        key_size_in_bytes, AesSivParameters::Variant::kNoPrefix);
    ASSERT_THAT(params, IsOk());
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
  EXPECT_EQ(skipped_test_groups, 1);
}

TEST(AesSivBoringSslTest, FipsOnly) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }
  const AesSivTestVector& test_vector32 =
      GetAesSivTestVector(32, AesSivParameters::Variant::kNoPrefix);
  EXPECT_THAT(NewAesSivBoringSsl(test_vector32.key),
              StatusIs(absl::StatusCode::kInternal));
  const AesSivTestVector& test_vector64 =
      GetAesSivTestVector(64, AesSivParameters::Variant::kNoPrefix);
  EXPECT_THAT(NewAesSivBoringSsl(test_vector64.key),
              StatusIs(absl::StatusCode::kInternal));
}

absl::StatusOr<AesSivKey> CreateKeyFromHex(
    absl::string_view key_hex,
    AesSivParameters::Variant variant = AesSivParameters::Variant::kNoPrefix,
    absl::optional<int> id_requirement = std::nullopt) {
  std::string key_bytes = test::HexDecodeOrDie(key_hex);
  absl::StatusOr<AesSivParameters> params =
      AesSivParameters::Create(key_bytes.size(), variant);
  if (!params.ok()) {
    return params.status();
  }
  return AesSivKey::Create(
      *params, RestrictedData(key_bytes, InsecureSecretKeyAccess::Get()),
      id_requirement, GetPartialKeyAccess());
}

struct MultiAdTestVector {
  std::string name;
  std::string key_hex;
  std::vector<std::string> ads_hex;
  std::string plaintext_hex;
  std::string ciphertext_hex;
};

// Test vectors from RFC 5297 Appendix A.1, Appendix A.2, and OpenSSL AES-SIV
// multi-AD test vectors (matching Tink Java's AesSivTest).
std::vector<MultiAdTestVector> GetMultiAdTestVectors() {
  return {
      {
          /*name=*/"Rfc5297A1_32ByteKey_SingleAd",
          /*key_hex=*/
          "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
          "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
          /*ads_hex=*/{"101112131415161718191a1b1c1d1e1f2021222324252627"},
          /*plaintext_hex=*/"112233445566778899aabbccddee",
          /*ciphertext_hex=*/
          "85632d07c6e8f37f950acd320a2ecc93"
          "40c02b9690c4dc04daef7f6afe5c",
      },
      {
          /*name=*/"32ByteKey_ZeroAds",
          /*key_hex=*/
          "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
          "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
          /*ads_hex=*/{},
          /*plaintext_hex=*/"112233445566778899aabbccddee",
          /*ciphertext_hex=*/
          "f1c5fdeac1f15a26779c1501f9fb7588"
          "27e946c669088ab06da58c5c831c",
      },
      {
          /*name=*/"32ByteKey_SingleEmptyAd",
          /*key_hex=*/
          "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
          "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
          /*ads_hex=*/{""},
          /*plaintext_hex=*/"112233445566778899aabbccddee",
          /*ciphertext_hex=*/
          "d1022f5b3664e5a4dfaf90f85be6f28a"
          "b66cff6b8eca0b79f083b39a0901",
      },
      {
          /*name=*/"Rfc5297A2_32ByteKey_ThreeAds",
          /*key_hex=*/
          "7f7e7d7c7b7a79787776757473727170"
          "404142434445464748494a4b4c4d4e4f",
          /*ads_hex=*/
          {
              "00112233445566778899aabbccddeeff"
              "deaddadadeaddadaffeeddccbbaa9988"
              "7766554433221100",
              "102030405060708090a0",
              "09f911029d74e35bd84156c5635688c0",
          },
          /*plaintext_hex=*/
          "7468697320697320736f6d6520706c61"
          "696e7465787420746f20656e63727970"
          "74207573696e67205349562d414553",
          /*ciphertext_hex=*/
          "7bdb6e3b432667eb06f4d14bff2fbd0f"
          "cb900f2fddbe404326601965c889bf17"
          "dba77ceb094fa663b7a3f748ba8af829"
          "ea64ad544a272e9c485b62a3fd5c0d",
      },
      {
          /*name=*/"32ByteKey_ThreeAdsMiddleEmpty",
          /*key_hex=*/
          "7f7e7d7c7b7a79787776757473727170"
          "404142434445464748494a4b4c4d4e4f",
          /*ads_hex=*/
          {
              "00112233445566778899aabbccddeeff"
              "deaddadadeaddadaffeeddccbbaa9988"
              "7766554433221100",
              "",
              "09f911029d74e35bd84156c5635688c0",
          },
          /*plaintext_hex=*/
          "7468697320697320736f6d6520706c61"
          "696e7465787420746f20656e63727970"
          "74207573696e67205349562d414553",
          /*ciphertext_hex=*/
          "83ce6593a8fa67eb6fcd2819cedfc011"
          "30d937b42f71f71f93fc2d8d702d3eac"
          "8dc7651eefcd81120081ff29d626f97f"
          "3de17f2969b691c91b69b652bf3a6d",
      },
      {
          /*name=*/"32ByteKey_ThreeAdsFirstEmpty",
          /*key_hex=*/
          "7f7e7d7c7b7a79787776757473727170"
          "404142434445464748494a4b4c4d4e4f",
          /*ads_hex=*/
          {
              "",
              "00112233445566778899aabbccddeeff"
              "deaddadadeaddadaffeeddccbbaa9988"
              "7766554433221100",
              "09f911029d74e35bd84156c5635688c0",
          },
          /*plaintext_hex=*/
          "7468697320697320736f6d6520706c61"
          "696e7465787420746f20656e63727970"
          "74207573696e67205349562d414553",
          /*ciphertext_hex=*/
          "77dd4a44f5a6b41302121ee7f378de25"
          "0fcd664c922464c88939d71fad7aefb8"
          "64e501b0848a07d39201c1067a7288f3"
          "dadf0131a823a0bc3d588e8564a5fe",
      },
      {
          /*name=*/"64ByteKey_SingleAd",
          /*key_hex=*/
          "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
          "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
          "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
          "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0",
          /*ads_hex=*/{"101112131415161718191a1b1c1d1e1f2021222324252627"},
          /*plaintext_hex=*/"112233445566778899aabbccddee",
          /*ciphertext_hex=*/
          "724dfb2eaf94dbb19b0ba3a299a0801e"
          "f3b05a55498ec2552690b89810e4",
      },
  };
}

using MultiAdTestVectorTest = TestWithParam<MultiAdTestVector>;

TEST_P(MultiAdTestVectorTest, EncryptAndDecryptMultiAdVectors) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const MultiAdTestVector& tc = GetParam();
  std::string plaintext = test::HexDecodeOrDie(tc.plaintext_hex);
  std::string raw_ciphertext = test::HexDecodeOrDie(tc.ciphertext_hex);
  std::vector<std::string> decoded_ads;
  decoded_ads.reserve(tc.ads_hex.size());
  for (const std::string& aad_hex : tc.ads_hex) {
    decoded_ads.push_back(test::HexDecodeOrDie(aad_hex));
  }
  std::vector<absl::string_view> aad_views(decoded_ads.begin(),
                                           decoded_ads.end());

  // Verify with kNoPrefix, kTink, and kCrunchy variants.
  for (AesSivParameters::Variant variant :
       {AesSivParameters::Variant::kNoPrefix, AesSivParameters::Variant::kTink,
        AesSivParameters::Variant::kCrunchy}) {
    std::optional<int> id_requirement =
        variant == AesSivParameters::Variant::kNoPrefix
            ? std::nullopt
            : std::optional<int>(0x11223344);
    absl::StatusOr<AesSivKey> key =
        CreateKeyFromHex(tc.key_hex, variant, id_requirement);
    ASSERT_THAT(key, IsOk());

    absl::StatusOr<std::unique_ptr<DeterministicAeads>> daead =
        NewAesSivBoringSsl(*key);
    ASSERT_THAT(daead, IsOk());

    std::string expected_ciphertext =
        absl::StrCat(key->GetOutputPrefix(), raw_ciphertext);
    EXPECT_THAT((*daead)->EncryptDeterministicallyWithAssociatedDatas(
                    plaintext, aad_views),
                IsOkAndHolds(expected_ciphertext));
    EXPECT_THAT((*daead)->DecryptDeterministicallyWithAssociatedDatas(
                    expected_ciphertext, aad_views),
                IsOkAndHolds(plaintext));
  }
}

INSTANTIATE_TEST_SUITE_P(
    MultiAdTestVectors, MultiAdTestVectorTest,
    ValuesIn(GetMultiAdTestVectors()),
    [](const testing::TestParamInfo<MultiAdTestVector>& info) {
      return info.param.name;
    });

TEST(AesSivBoringSslTest, AssociatedDataFramingAndOrdering) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  absl::StatusOr<AesSivKey> key = CreateKeyFromHex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<DeterministicAeads>> daead =
      NewAesSivBoringSsl(*key);
  ASSERT_THAT(daead, IsOk());

  // 0 ADs != 1 empty AD.
  absl::StatusOr<std::string> ct_zero_ads =
      (*daead)->EncryptDeterministicallyWithAssociatedDatas("plaintext", {});
  absl::StatusOr<std::string> ct_one_empty_ad =
      (*daead)->EncryptDeterministicallyWithAssociatedDatas("plaintext", {""});
  ASSERT_THAT(ct_zero_ads, IsOk());
  ASSERT_THAT(ct_one_empty_ad, IsOk());
  EXPECT_THAT(*ct_zero_ads, Ne(*ct_one_empty_ad));
  EXPECT_THAT(
      (*daead)->DecryptDeterministicallyWithAssociatedDatas(*ct_zero_ads, {""}),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT((*daead)->DecryptDeterministicallyWithAssociatedDatas(
                  *ct_one_empty_ad, {}),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Single-AD EncryptDeterministically("", ...) equals 1 empty AD {""}, not {}.
  EXPECT_THAT((*daead)->EncryptDeterministically("plaintext", ""),
              IsOkAndHolds(*ct_one_empty_ad));
  absl::string_view null_sv;
  EXPECT_THAT((*daead)->EncryptDeterministically("plaintext", null_sv),
              IsOkAndHolds(*ct_one_empty_ad));
  EXPECT_THAT((*daead)->EncryptDeterministicallyWithAssociatedDatas(
                  null_sv, {null_sv, null_sv}),
              IsOk());

  // Boundary sensitivity: {"ab", "c"} != {"a", "bc"}.
  absl::StatusOr<std::string> ct_ab_c =
      (*daead)->EncryptDeterministicallyWithAssociatedDatas("plaintext",
                                                            {"ab", "c"});
  absl::StatusOr<std::string> ct_a_bc =
      (*daead)->EncryptDeterministicallyWithAssociatedDatas("plaintext",
                                                            {"a", "bc"});
  ASSERT_THAT(ct_ab_c, IsOk());
  ASSERT_THAT(ct_a_bc, IsOk());
  EXPECT_THAT(*ct_ab_c, Ne(*ct_a_bc));
  EXPECT_THAT((*daead)->DecryptDeterministicallyWithAssociatedDatas(
                  *ct_ab_c, {"a", "bc"}),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Order sensitivity: {"a", "b"} != {"b", "a"}.
  absl::StatusOr<std::string> ct_a_b =
      (*daead)->EncryptDeterministicallyWithAssociatedDatas("plaintext",
                                                            {"a", "b"});
  absl::StatusOr<std::string> ct_b_a =
      (*daead)->EncryptDeterministicallyWithAssociatedDatas("plaintext",
                                                            {"b", "a"});
  ASSERT_THAT(ct_a_b, IsOk());
  ASSERT_THAT(ct_b_a, IsOk());
  EXPECT_THAT(*ct_a_b, Ne(*ct_b_a));
  EXPECT_THAT((*daead)->DecryptDeterministicallyWithAssociatedDatas(*ct_a_b,
                                                                    {"b", "a"}),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesSivBoringSslTest, MaxAssociatedDatasLimit) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  absl::StatusOr<AesSivKey> key = CreateKeyFromHex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<DeterministicAeads>> daead =
      NewAesSivBoringSsl(*key);
  ASSERT_THAT(daead, IsOk());

  // Up to 126 associated datas are permitted by RFC 5297 Section 7.
  std::vector<absl::string_view> max_aads(126, "ad");
  absl::StatusOr<std::string> ciphertext =
      (*daead)->EncryptDeterministicallyWithAssociatedDatas("plaintext",
                                                            max_aads);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*daead)->DecryptDeterministicallyWithAssociatedDatas(*ciphertext,
                                                                    max_aads),
              IsOkAndHolds("plaintext"));

  // 127 associated datas must be rejected on both encrypt and decrypt.
  std::vector<absl::string_view> too_many_aads(127, "ad");
  EXPECT_THAT((*daead)
                  ->EncryptDeterministicallyWithAssociatedDatas("plaintext",
                                                                too_many_aads)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT((*daead)
                  ->DecryptDeterministicallyWithAssociatedDatas(*ciphertext,
                                                                too_many_aads)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
