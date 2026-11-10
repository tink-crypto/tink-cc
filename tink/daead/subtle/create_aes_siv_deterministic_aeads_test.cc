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

#include "tink/daead/subtle/create_aes_siv_deterministic_aeads.h"

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
#include "tink/daead/aes_siv_key.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/daead/internal/aes_siv_test_vectors.h"
#include "tink/daead/subtle/deterministic_aeads.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/test_util.h"

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
using ::testing::Ne;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

absl::StatusOr<AesSivKey> CreateKeyFromHex(
    absl::string_view key_hex,
    AesSivParameters::Variant variant = AesSivParameters::Variant::kNoPrefix,
    std::optional<int> id_requirement = std::nullopt) {
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

using CreateAesSivDeterministicAeadsTest = TestWithParam<AesSivTestVector>;

INSTANTIATE_TEST_SUITE_P(CreateAesSivDeterministicAeadsTest,
                         CreateAesSivDeterministicAeadsTest,
                         ValuesIn(CreateAesSivTestVectors()));

TEST_P(CreateAesSivDeterministicAeadsTest, EncryptAndDecrypt) {
  const AesSivTestVector& test_vector = GetParam();
  if (test_vector.key.GetParameters().KeySizeInBytes() == 48) {
    EXPECT_THAT(CreateAesSivDeterministicAeads(test_vector.key),
                StatusIs(absl::StatusCode::kInvalidArgument));
    return;
  }

  absl::StatusOr<std::unique_ptr<DeterministicAeads>> daead =
      CreateAesSivDeterministicAeads(test_vector.key);
  ASSERT_THAT(daead, IsOk());

  EXPECT_THAT((*daead)->EncryptDeterministically(test_vector.plaintext,
                                                 test_vector.aad),
              IsOkAndHolds(test_vector.ciphertext));
  EXPECT_THAT((*daead)->DecryptDeterministically(test_vector.ciphertext,
                                                 test_vector.aad),
              IsOkAndHolds(test_vector.plaintext));

  EXPECT_THAT((*daead)->EncryptDeterministicallyWithAssociatedDatas(
                  test_vector.plaintext, {test_vector.aad}),
              IsOkAndHolds(test_vector.ciphertext));
  EXPECT_THAT((*daead)->DecryptDeterministicallyWithAssociatedDatas(
                  test_vector.ciphertext, {test_vector.aad}),
              IsOkAndHolds(test_vector.plaintext));
}

TEST_P(CreateAesSivDeterministicAeadsTest, DecryptFailsWithModifiedCiphertext) {
  const AesSivTestVector& test_vector = GetParam();
  if (test_vector.key.GetParameters().KeySizeInBytes() == 48) {
    return;
  }

  absl::StatusOr<std::unique_ptr<DeterministicAeads>> daead =
      CreateAesSivDeterministicAeads(test_vector.key);
  ASSERT_THAT(daead, IsOk());

  for (size_t i = 0; i < test_vector.ciphertext.size(); ++i) {
    std::string modified_ciphertext = test_vector.ciphertext;
    modified_ciphertext[i] ^= 1;
    EXPECT_THAT((*daead)->DecryptDeterministicallyWithAssociatedDatas(
                    modified_ciphertext, {test_vector.aad}),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST_P(CreateAesSivDeterministicAeadsTest,
       DecryptFailsWithWrongAssociatedDatas) {
  const AesSivTestVector& test_vector = GetParam();
  if (test_vector.key.GetParameters().KeySizeInBytes() == 48) {
    return;
  }

  absl::StatusOr<std::unique_ptr<DeterministicAeads>> daead =
      CreateAesSivDeterministicAeads(test_vector.key);
  ASSERT_THAT(daead, IsOk());

  EXPECT_THAT((*daead)->DecryptDeterministicallyWithAssociatedDatas(
                  test_vector.ciphertext, {"wrong_aad"}),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT((*daead)->DecryptDeterministicallyWithAssociatedDatas(
                  test_vector.ciphertext, {}),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT((*daead)->DecryptDeterministicallyWithAssociatedDatas(
                  test_vector.ciphertext, {test_vector.aad, "extra"}),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAesSivDeterministicAeadsTest, Rfc5297MultiAdTestVector) {
  // RFC 5297 Appendix A.2: 32-byte key with 3 associated data components.
  std::string key_hex =
      "7f7e7d7c7b7a79787776757473727170"
      "404142434445464748494a4b4c4d4e4f";
  std::vector<std::string> decoded_aads = {
      test::HexDecodeOrDie("00112233445566778899aabbccddeeff"
                           "deaddadadeaddadaffeeddccbbaa9988"
                           "7766554433221100"),
      test::HexDecodeOrDie("102030405060708090a0"),
      test::HexDecodeOrDie("09f911029d74e35bd84156c5635688c0"),
  };
  std::vector<absl::string_view> aad_views(decoded_aads.begin(),
                                           decoded_aads.end());
  std::string plaintext = test::HexDecodeOrDie(
      "7468697320697320736f6d6520706c61"
      "696e7465787420746f20656e63727970"
      "74207573696e67205349562d414553");
  std::string raw_ciphertext = test::HexDecodeOrDie(
      "7bdb6e3b432667eb06f4d14bff2fbd0f"
      "cb900f2fddbe404326601965c889bf17"
      "dba77ceb094fa663b7a3f748ba8af829"
      "ea64ad544a272e9c485b62a3fd5c0d");

  for (AesSivParameters::Variant variant :
       {AesSivParameters::Variant::kNoPrefix, AesSivParameters::Variant::kTink,
        AesSivParameters::Variant::kCrunchy}) {
    std::optional<int> id_requirement =
        variant == AesSivParameters::Variant::kNoPrefix
            ? std::nullopt
            : std::optional<int>(0x11223344);
    absl::StatusOr<AesSivKey> key =
        CreateKeyFromHex(key_hex, variant, id_requirement);
    ASSERT_THAT(key, IsOk());

    absl::StatusOr<std::unique_ptr<DeterministicAeads>> daead =
        CreateAesSivDeterministicAeads(*key);
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

TEST(CreateAesSivDeterministicAeadsTest, AssociatedDataFramingAndOrdering) {
  absl::StatusOr<AesSivKey> key = CreateKeyFromHex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<DeterministicAeads>> daead =
      CreateAesSivDeterministicAeads(*key);
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

  // Single-AD EncryptDeterministically("", ...) equals 1 empty AD {""}, not {}.
  EXPECT_THAT((*daead)->EncryptDeterministically("plaintext", ""),
              IsOkAndHolds(*ct_one_empty_ad));

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

TEST(CreateAesSivDeterministicAeadsTest, MaxAssociatedDatasLimit) {
  absl::StatusOr<AesSivKey> key = CreateKeyFromHex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<DeterministicAeads>> daead =
      CreateAesSivDeterministicAeads(*key);
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
  EXPECT_THAT((*daead)->EncryptDeterministicallyWithAssociatedDatas(
                  "plaintext", too_many_aads),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT((*daead)->DecryptDeterministicallyWithAssociatedDatas(
                  *ciphertext, too_many_aads),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAesSivDeterministicAeadsTest, DecryptWithWrongPrefixFails) {
  const AesSivTestVector& test_vector =
      GetAesSivTestVector(64, AesSivParameters::Variant::kTink);
  absl::StatusOr<std::unique_ptr<DeterministicAeads>> daead =
      CreateAesSivDeterministicAeads(test_vector.key);
  ASSERT_THAT(daead, IsOk());

  ASSERT_TRUE(absl::StartsWith(test_vector.ciphertext,
                               test_vector.key.GetOutputPrefix()));
  std::string wrong_prefix_ciphertext =
      absl::StrCat("\x01\x99\x99\x99\x99",
                   absl::string_view(test_vector.ciphertext)
                       .substr(test_vector.key.GetOutputPrefix().size()));
  EXPECT_THAT((*daead)->DecryptDeterministicallyWithAssociatedDatas(
                  wrong_prefix_ciphertext, {test_vector.aad}),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
