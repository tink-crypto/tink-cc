// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/aead/internal/cord_aes_gcm_siv_boringssl.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "absl/strings/cord_test_helpers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/aead.h"
#endif
#include "openssl/err.h"
#include "openssl/opensslv.h"
#include "tink/aead.h"
#include "tink/aead/aes_gcm_siv_key.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/aes_gcm_siv_test_vectors.h"
#include "tink/aead/internal/wycheproof_aead.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_util.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/aes_gcm_siv_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

constexpr absl::string_view kKey128Hex = "000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kKey256Hex =
    "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kMessage = "Some data to encrypt.";
constexpr absl::string_view kLongMessage =
    "This is some long message which will be fragmented into multiple blocks.";
constexpr absl::string_view kAssociatedData = "Some associated data.";

constexpr int kIvSizeInBytes = 12;
constexpr int kTagSizeInBytes = 16;

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::TestWithParam;
using ::testing::ValuesIn;
using Variant = AesGcmSivParameters::Variant;

bool IsAesGcmSivSupported() {
  if (!internal::IsBoringSsl()) {
    return false;
  }
#if defined(BORINGSSL_FIPS) || defined(TINK_USE_ONLY_FIPS)
  return false;
#endif
  return !internal::IsFipsModeEnabled();
}

// TOOD(b/556356282): remove once CRYPTO_IOVEC_MAX is no longer used in OSS.
bool SupportsArbitraryIOVecs() {
#ifdef CRYPTO_IOVEC_MAX
  return false;
#endif
  return true;
}

class CordAesGcmSivBoringSslTest : public ::testing::Test {
 protected:
  void SetUp() override {
    if (!IsAesGcmSivSupported()) {
      GTEST_SKIP() << "AES-GCM-SIV is not supported in BoringSSL FIPS, "
                      "OpenSSL, or FIPS-only mode";
    }
  }
};

class CordAesGcmSivBoringSslTestVectorTest
    : public TestWithParam<internal::AeadTestVector> {
 protected:
  void SetUp() override {
    if (!IsAesGcmSivSupported()) {
      GTEST_SKIP() << "AES-GCM-SIV is not supported in BoringSSL FIPS, "
                      "OpenSSL, or FIPS-only mode";
    }
  }
};

class CordAesGcmSivBoringSslWycheproofTest
    : public TestWithParam<WycheproofTestVector> {
 protected:
  void SetUp() override {
    if (!IsAesGcmSivSupported()) {
      GTEST_SKIP() << "AES-GCM-SIV is not supported in BoringSSL FIPS, "
                      "OpenSSL, or FIPS-only mode";
    }
  }
};

absl::StatusOr<AesGcmSivKey> CreateKey(
    int key_size_in_bytes, Variant variant = Variant::kNoPrefix,
    std::optional<int> id_requirement = std::nullopt) {
  absl::StatusOr<AesGcmSivParameters> parameters =
      AesGcmSivParameters::Create(key_size_in_bytes, variant);
  if (!parameters.ok()) {
    return parameters.status();
  }
  return AesGcmSivKey::Create(*parameters, RestrictedData(key_size_in_bytes),
                              id_requirement, GetPartialKeyAccess());
}

absl::StatusOr<AesGcmSivKey> CreateKey(
    absl::string_view key_bytes, Variant variant = Variant::kNoPrefix,
    std::optional<int> id_requirement = std::nullopt) {
  absl::StatusOr<AesGcmSivParameters> parameters =
      AesGcmSivParameters::Create(key_bytes.size(), variant);
  if (!parameters.ok()) {
    return parameters.status();
  }
  RestrictedData secret(key_bytes, InsecureSecretKeyAccess::Get());
  return AesGcmSivKey::Create(*parameters, secret, id_requirement,
                              GetPartialKeyAccess());
}

absl::StatusOr<std::unique_ptr<CordAead>> CreateCordAesGcmSiv(
    int key_size_in_bytes, Variant variant = Variant::kNoPrefix,
    std::optional<int> id_requirement = std::nullopt) {
  absl::StatusOr<AesGcmSivKey> key =
      CreateKey(key_size_in_bytes, variant, id_requirement);
  if (!key.ok()) {
    return key.status();
  }
  return NewCordAesGcmSivBoringSsl(*key);
}

absl::Cord MakeFragmentedCord(absl::string_view text, int chunk_size) {
  if (text.empty()) {
    return absl::Cord();
  }
  return absl::MakeFragmentedCord(
      absl::StrSplit(text, absl::ByLength(chunk_size)));
}

std::string GetError() {
  auto err = ERR_peek_last_error();
  if (err == 0) {
    return "";
  }
  std::string lib(ERR_lib_error_string(err));
  std::string func(ERR_func_error_string(err));
  std::string reason(ERR_reason_error_string(err));
  return absl::StrCat(lib, ":", func, ":", reason);
}

TEST_P(CordAesGcmSivBoringSslTestVectorTest, Decrypt) {
  const internal::AeadTestVector& test_vector = GetParam();
  const AesGcmSivKey& key =
      dynamic_cast<const AesGcmSivKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<CordAead>> aead =
      NewCordAesGcmSivBoringSsl(key);
  ASSERT_THAT(aead, IsOk());
  ASSERT_THAT((*aead)->Decrypt(absl::Cord(test_vector.ciphertext),
                               absl::Cord(test_vector.associated_data)),
              IsOkAndHolds(test_vector.plaintext));
}

TEST_P(CordAesGcmSivBoringSslTestVectorTest, EncryptDecrypt) {
  const internal::AeadTestVector& test_vector = GetParam();
  const AesGcmSivKey& key =
      dynamic_cast<const AesGcmSivKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<CordAead>> aead =
      NewCordAesGcmSivBoringSsl(key);
  ASSERT_THAT(aead, IsOk());
  absl::StatusOr<absl::Cord> ct =
      (*aead)->Encrypt(absl::Cord(test_vector.plaintext),
                       absl::Cord(test_vector.associated_data));
  ASSERT_THAT(ct, IsOk());
  if (!key.GetOutputPrefix().empty()) {
    EXPECT_TRUE(ct->StartsWith(key.GetOutputPrefix()));
  }
  ASSERT_THAT((*aead)->Decrypt(*ct, absl::Cord(test_vector.associated_data)),
              IsOkAndHolds(test_vector.plaintext));
}

INSTANTIATE_TEST_SUITE_P(CordAesGcmSivBoringSslTestVectorTests,
                         CordAesGcmSivBoringSslTestVectorTest,
                         ValuesIn(internal::CreateAesGcmSivTestVectors()));

TEST_F(CordAesGcmSivBoringSslTest, EncryptDecrypt128BitKey) {
  absl::StatusOr<std::unique_ptr<CordAead>> aead = CreateCordAesGcmSiv(16);
  ASSERT_THAT(aead, IsOk());

  absl::Cord message(kMessage);
  absl::Cord ad(kAssociatedData);
  absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(message, ad);
  ASSERT_THAT(ct, IsOk());
  EXPECT_THAT(*ct, SizeIs(message.size() + kIvSizeInBytes + kTagSizeInBytes));

  ASSERT_THAT((*aead)->Decrypt(*ct, ad), IsOkAndHolds(message));
}

TEST_F(CordAesGcmSivBoringSslTest, EncryptDecrypt256BitKey) {
  absl::StatusOr<std::unique_ptr<CordAead>> aead = CreateCordAesGcmSiv(32);
  ASSERT_THAT(aead, IsOk());

  absl::Cord message(kMessage);
  absl::Cord ad(kAssociatedData);
  absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(message, ad);
  ASSERT_THAT(ct, IsOk());
  EXPECT_THAT(*ct, SizeIs(message.size() + kIvSizeInBytes + kTagSizeInBytes));

  ASSERT_THAT((*aead)->Decrypt(*ct, ad), IsOkAndHolds(message));
}

TEST_F(CordAesGcmSivBoringSslTest, EmptyptAndAssociatedData) {
  absl::StatusOr<std::unique_ptr<CordAead>> aead = CreateCordAesGcmSiv(16);
  ASSERT_THAT(aead, IsOk());

  absl::Cord empty_pt;
  absl::Cord empty_ad;
  absl::Cord non_empty_pt(kMessage);
  absl::Cord non_empty_ad(kAssociatedData);

  // Empty pt, empty associated data
  absl::StatusOr<absl::Cord> ct1 = (*aead)->Encrypt(empty_pt, empty_ad);
  ASSERT_THAT(ct1, IsOk());
  EXPECT_THAT(*ct1, SizeIs(kIvSizeInBytes + kTagSizeInBytes));
  EXPECT_THAT((*aead)->Decrypt(*ct1, empty_ad), IsOkAndHolds(empty_pt));

  // Empty pt, non-empty associated data
  absl::StatusOr<absl::Cord> ct2 = (*aead)->Encrypt(empty_pt, non_empty_ad);
  ASSERT_THAT(ct2, IsOk());
  EXPECT_THAT(*ct2, SizeIs(kIvSizeInBytes + kTagSizeInBytes));
  EXPECT_THAT((*aead)->Decrypt(*ct2, non_empty_ad), IsOkAndHolds(empty_pt));

  // Non-empty pt, empty associated data
  absl::StatusOr<absl::Cord> ct3 = (*aead)->Encrypt(non_empty_pt, empty_ad);
  ASSERT_THAT(ct3, IsOk());
  EXPECT_THAT(*ct3,
              SizeIs(non_empty_pt.size() + kIvSizeInBytes + kTagSizeInBytes));
  EXPECT_THAT((*aead)->Decrypt(*ct3, empty_ad), IsOkAndHolds(non_empty_pt));

  // Non-empty pt, non-empty associated data
  absl::StatusOr<absl::Cord> ct4 = (*aead)->Encrypt(non_empty_pt, non_empty_ad);
  ASSERT_THAT(ct4, IsOk());
  EXPECT_THAT(*ct4,
              SizeIs(non_empty_pt.size() + kIvSizeInBytes + kTagSizeInBytes));
  EXPECT_THAT((*aead)->Decrypt(*ct4, non_empty_ad), IsOkAndHolds(non_empty_pt));
}

TEST_F(CordAesGcmSivBoringSslTest, OutputPrefixTink) {
  absl::StatusOr<AesGcmSivKey> key =
      CreateKey(32, Variant::kTink, /*id_requirement=*/0x01020304);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<CordAead>> aead =
      NewCordAesGcmSivBoringSsl(*key);
  ASSERT_THAT(aead, IsOk());

  absl::Cord pt("some pt");
  absl::Cord aad("some ad");
  absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(pt, aad);
  ASSERT_THAT(ct, IsOk());
  EXPECT_THAT(*ct, SizeIs(5 + pt.size() + kIvSizeInBytes + kTagSizeInBytes));
  EXPECT_TRUE(ct->StartsWith(key->GetOutputPrefix()));
  EXPECT_THAT((*aead)->Decrypt(*ct, aad), IsOkAndHolds(pt));
}

TEST_F(CordAesGcmSivBoringSslTest, OutputPrefixCrunchy) {
  absl::StatusOr<AesGcmSivKey> key =
      CreateKey(32, Variant::kCrunchy, /*id_requirement=*/0x01020304);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<CordAead>> aead =
      NewCordAesGcmSivBoringSsl(*key);
  ASSERT_THAT(aead, IsOk());

  absl::Cord pt("some pt");
  absl::Cord aad("some ad");
  absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(pt, aad);
  ASSERT_THAT(ct, IsOk());
  EXPECT_THAT(*ct, SizeIs(5 + pt.size() + kIvSizeInBytes + kTagSizeInBytes));
  EXPECT_TRUE(ct->StartsWith(key->GetOutputPrefix()));
  EXPECT_THAT((*aead)->Decrypt(*ct, aad), IsOkAndHolds(pt));
}

TEST_F(CordAesGcmSivBoringSslTest, CorruptPrefixFails) {
  absl::StatusOr<AesGcmSivKey> key =
      CreateKey(32, Variant::kTink, /*id_requirement=*/0x01020304);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<CordAead>> aead =
      NewCordAesGcmSivBoringSsl(*key);
  ASSERT_THAT(aead, IsOk());

  absl::Cord pt("some pt");
  absl::Cord aad("some ad");
  absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(pt, aad);
  ASSERT_THAT(ct, IsOk());

  std::string corrupted_ct = std::string(ct->Flatten());
  corrupted_ct[0] ^= 0x42;
  EXPECT_THAT((*aead)->Decrypt(absl::Cord(corrupted_ct), aad).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(CordAesGcmSivBoringSslTest, NonDeterministicIvOnEveryEncryption) {
  absl::StatusOr<std::unique_ptr<CordAead>> aead = CreateCordAesGcmSiv(16);
  ASSERT_THAT(aead, IsOk());

  absl::Cord pt(kMessage);
  absl::Cord aad(kAssociatedData);
  absl::StatusOr<absl::Cord> ct1 = (*aead)->Encrypt(pt, aad);
  ASSERT_THAT(ct1, IsOk());
  absl::StatusOr<absl::Cord> ct2 = (*aead)->Encrypt(pt, aad);
  ASSERT_THAT(ct2, IsOk());

  EXPECT_NE(*ct1, *ct2);
  EXPECT_THAT((*aead)->Decrypt(*ct1, aad), IsOkAndHolds(pt));
  EXPECT_THAT((*aead)->Decrypt(*ct2, aad), IsOkAndHolds(pt));
}

TEST_F(CordAesGcmSivBoringSslTest,
       SmallChunkFragmentedPlaintextAndAssociatedData) {
  absl::StatusOr<std::unique_ptr<CordAead>> aead = CreateCordAesGcmSiv(16);
  ASSERT_THAT(aead, IsOk());

  absl::Cord message_cord = MakeFragmentedCord(kLongMessage, 3);
  absl::Cord aad_cord = MakeFragmentedCord(kAssociatedData, 3);

  absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(message_cord, aad_cord);
  // TOOD(b/556356282): remove once CRYPTO_IOVEC_MAX is no longer used in OSS.
  if (SupportsArbitraryIOVecs()) {
    ASSERT_THAT(ct, IsOk());
    EXPECT_THAT(*ct,
                SizeIs(message_cord.size() + kIvSizeInBytes + kTagSizeInBytes));
    ASSERT_THAT((*aead)->Decrypt(*ct, aad_cord), IsOkAndHolds(kLongMessage));
  } else {
    EXPECT_THAT(ct, StatusIs(absl::StatusCode::kInternal,
                             testing::HasSubstr("CRYPTO_IOVEC_MAX")));
  }
}

TEST_F(CordAesGcmSivBoringSslTest, FragmentedCiphertextAndAssociatedData) {
  // TOOD(b/556356282): remove once CRYPTO_IOVEC_MAX is no longer used in OSS.
  if (!SupportsArbitraryIOVecs()) {
    GTEST_SKIP() << "CRYPTO_IOVEC_MAX is set to a small value";
  }
  absl::StatusOr<std::unique_ptr<CordAead>> aead = CreateCordAesGcmSiv(16);
  ASSERT_THAT(aead, IsOk());

  absl::Cord message_cord(kLongMessage);
  absl::Cord aad_cord(kAssociatedData);
  absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(message_cord, aad_cord);
  ASSERT_THAT(ct, IsOk());

  absl::Cord fragmented_ct = MakeFragmentedCord(ct->Flatten(), 3);
  absl::Cord fragmented_ad = MakeFragmentedCord(aad_cord.Flatten(), 3);
  ASSERT_THAT((*aead)->Decrypt(fragmented_ct, fragmented_ad),
              IsOkAndHolds(kLongMessage));
}

TEST_F(CordAesGcmSivBoringSslTest, LargePayloadMultiCordBuffer) {
  // TOOD(b/556356282): remove once CRYPTO_IOVEC_MAX is no longer used in OSS.
  if (!SupportsArbitraryIOVecs()) {
    GTEST_SKIP() << "CRYPTO_IOVEC_MAX is set to a small value";
  }

  constexpr int kLargeSize = 256 * 1024;  // 256 KiB
  absl::Cord msg(subtle::Random::GetRandomBytes(kLargeSize));
  absl::Cord aad(kAssociatedData);

  absl::StatusOr<std::unique_ptr<CordAead>> aead = CreateCordAesGcmSiv(32);
  ASSERT_THAT(aead, IsOk());
  absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(msg, aad);
  ASSERT_THAT(ct, IsOk());
  EXPECT_THAT(*ct, SizeIs(msg.size() + kIvSizeInBytes + kTagSizeInBytes));
  EXPECT_THAT((*aead)->Decrypt(*ct, aad), IsOkAndHolds(msg));
}

TEST_F(CordAesGcmSivBoringSslTest, BufferBoundaryChunkAlignmentEdgeCases) {
  if (!SupportsArbitraryIOVecs()) {
    GTEST_SKIP() << "CRYPTO_IOVEC_MAX is set to a small value";
  }

  absl::StatusOr<std::unique_ptr<CordAead>> aead = CreateCordAesGcmSiv(16);
  ASSERT_THAT(aead, IsOk());
  absl::Cord aad(kAssociatedData);
  constexpr int kKiB = 1024;
  for (int size :
       {64 * kKiB - 1, 64 * kKiB, 64 * kKiB + 1, 128 * kKiB, 256 * kKiB + 13}) {
    std::string message = subtle::Random::GetRandomBytes(size);

    // Unfragmented
    absl::Cord unfragmented_msg(message);
    absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(unfragmented_msg, aad);
    ASSERT_THAT(ct, IsOk()) << "Failed encrypt for size " << size;
    EXPECT_THAT(*ct, SizeIs(size + kIvSizeInBytes + kTagSizeInBytes));
    ASSERT_THAT((*aead)->Decrypt(*ct, aad), IsOkAndHolds(message))
        << "Failed decrypt for size " << size;

    // Fragmented with chunks crossing buffer boundaries (70 KiB)
    absl::Cord fragmented_msg = MakeFragmentedCord(message, 70 * 1024);
    absl::StatusOr<absl::Cord> ct_frag = (*aead)->Encrypt(fragmented_msg, aad);
    ASSERT_THAT(ct_frag, IsOk()) << "Failed frag encrypt for size " << size;
    ASSERT_THAT((*aead)->Decrypt(*ct_frag, aad), IsOkAndHolds(message))
        << "Failed frag decrypt for size " << size;
  }
}

TEST_F(CordAesGcmSivBoringSslTest, HighlyFragmentedPayloadManyIoVecs) {
  // TOOD(b/556356282): remove once CRYPTO_IOVEC_MAX is no longer used in OSS.
  if (!SupportsArbitraryIOVecs()) {
    GTEST_SKIP() << "CRYPTO_IOVEC_MAX is set to a small value";
  }
  absl::StatusOr<std::unique_ptr<CordAead>> aead = CreateCordAesGcmSiv(16);
  ASSERT_THAT(aead, IsOk());

  constexpr int kNumChunks = 2000;
  constexpr int kChunkSize = 16;
  std::string message = subtle::Random::GetRandomBytes(kNumChunks * kChunkSize);
  absl::Cord fragmented_message = MakeFragmentedCord(message, kChunkSize);
  std::string ad = subtle::Random::GetRandomBytes(kNumChunks * kChunkSize);
  absl::Cord fragmented_ad = MakeFragmentedCord(ad, kChunkSize);

  absl::StatusOr<absl::Cord> ct =
      (*aead)->Encrypt(fragmented_message, fragmented_ad);
  ASSERT_THAT(ct, IsOk());
  EXPECT_THAT(*ct, SizeIs(message.size() + kIvSizeInBytes + kTagSizeInBytes));

  ASSERT_THAT((*aead)->Decrypt(*ct, fragmented_ad), IsOkAndHolds(message));

  absl::Cord fragmented_ct = MakeFragmentedCord(ct->Flatten(), kChunkSize);
  ASSERT_THAT((*aead)->Decrypt(fragmented_ct, fragmented_ad),
              IsOkAndHolds(message));
}

TEST_F(CordAesGcmSivBoringSslTest, TamperedctFails) {
  absl::StatusOr<std::unique_ptr<CordAead>> aead = CreateCordAesGcmSiv(16);
  ASSERT_THAT(aead, IsOk());

  absl::Cord message(kMessage);
  absl::Cord ad(kAssociatedData);
  absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(message, ad);
  ASSERT_THAT(ct, IsOk());

  std::string ct_str = std::string(ct->Flatten());
  for (size_t i = 0; i < ct_str.size() * 8; ++i) {
    std::string modified_ct = ct_str;
    modified_ct[i / 8] ^= 1 << (i % 8);
    EXPECT_THAT((*aead)->Decrypt(absl::Cord(modified_ct), ad), Not(IsOk()))
        << "Bit flipped at index " << i;
  }
}

TEST_F(CordAesGcmSivBoringSslTest, TamperedAssociatedDataFails) {
  absl::StatusOr<std::unique_ptr<CordAead>> aead = CreateCordAesGcmSiv(16);
  ASSERT_THAT(aead, IsOk());

  absl::Cord message(kMessage);
  absl::Cord ad(kAssociatedData);
  absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(message, ad);
  ASSERT_THAT(ct, IsOk());

  std::string ad_str = std::string(ad.Flatten());
  for (size_t i = 0; i < ad_str.size() * 8; ++i) {
    std::string modified_ad = ad_str;
    modified_ad[i / 8] ^= 1 << (i % 8);
    EXPECT_THAT((*aead)->Decrypt(*ct, absl::Cord(modified_ad)), Not(IsOk()))
        << "Bit flipped in AD at index " << i;
  }
}

TEST_F(CordAesGcmSivBoringSslTest, TruncatedctFails) {
  absl::StatusOr<std::unique_ptr<CordAead>> aead = CreateCordAesGcmSiv(16);
  ASSERT_THAT(aead, IsOk());

  absl::Cord message(kMessage);
  absl::Cord ad(kAssociatedData);
  absl::StatusOr<absl::Cord> ct = (*aead)->Encrypt(message, ad);
  ASSERT_THAT(ct, IsOk());

  std::string ct_str = std::string(ct->Flatten());
  for (size_t i = 0; i < ct_str.size(); ++i) {
    std::string truncated_ct = ct_str.substr(0, i);
    EXPECT_THAT((*aead)->Decrypt(absl::Cord(truncated_ct), ad), Not(IsOk()))
        << "Truncated length " << i;
  }
}

TEST_F(CordAesGcmSivBoringSslTest, CrossCompatibilityWithSubtleAead) {
  absl::Cord message_cord(kMessage);
  absl::Cord aad_cord(kAssociatedData);

  // 128-bit key
  {
    absl::StatusOr<AesGcmSivKey> key128 =
        CreateKey(test::HexDecodeOrDie(kKey128Hex), Variant::kNoPrefix);
    ASSERT_THAT(key128, IsOk());
    absl::StatusOr<std::unique_ptr<CordAead>> cord_aead128 =
        NewCordAesGcmSivBoringSsl(*key128);
    ASSERT_THAT(cord_aead128, IsOk());
    absl::StatusOr<std::unique_ptr<Aead>> string_aead128 =
        subtle::AesGcmSivBoringSsl::New(
            key128->GetKeyBytes(GetPartialKeyAccess())
                .Get(InsecureSecretKeyAccess::Get()));
    ASSERT_THAT(string_aead128, IsOk());

    // Cord Encrypt -> String Decrypt
    absl::StatusOr<absl::Cord> ct_cord128 =
        (*cord_aead128)->Encrypt(message_cord, aad_cord);
    ASSERT_THAT(ct_cord128, IsOk());
    ASSERT_THAT(
        (*string_aead128)->Decrypt(ct_cord128->Flatten(), aad_cord.Flatten()),
        IsOkAndHolds(kMessage));

    // String Encrypt -> Cord Decrypt
    absl::StatusOr<std::string> ct_string128 =
        (*string_aead128)->Encrypt(kMessage, kAssociatedData);
    ASSERT_THAT(ct_string128, IsOk());
    ASSERT_THAT((*cord_aead128)->Decrypt(absl::Cord(*ct_string128), aad_cord),
                IsOkAndHolds(message_cord));
  }

  // 256-bit key
  {
    absl::StatusOr<AesGcmSivKey> key256 =
        CreateKey(test::HexDecodeOrDie(kKey256Hex), Variant::kNoPrefix);
    ASSERT_THAT(key256, IsOk());
    absl::StatusOr<std::unique_ptr<CordAead>> cord_aead256 =
        NewCordAesGcmSivBoringSsl(*key256);
    ASSERT_THAT(cord_aead256, IsOk());
    absl::StatusOr<std::unique_ptr<Aead>> string_aead256 =
        subtle::AesGcmSivBoringSsl::New(
            key256->GetKeyBytes(GetPartialKeyAccess())
                .Get(InsecureSecretKeyAccess::Get()));
    ASSERT_THAT(string_aead256, IsOk());

    // Cord Encrypt -> String Decrypt
    absl::StatusOr<absl::Cord> ct_cord256 =
        (*cord_aead256)->Encrypt(message_cord, aad_cord);
    ASSERT_THAT(ct_cord256, IsOk());
    ASSERT_THAT(
        (*string_aead256)->Decrypt(ct_cord256->Flatten(), aad_cord.Flatten()),
        IsOkAndHolds(kMessage));

    // String Encrypt -> Cord Decrypt
    absl::StatusOr<std::string> ct_string256 =
        (*string_aead256)->Encrypt(kMessage, kAssociatedData);
    ASSERT_THAT(ct_string256, IsOk());
    ASSERT_THAT((*cord_aead256)->Decrypt(absl::Cord(*ct_string256), aad_cord),
                IsOkAndHolds(message_cord));
  }
}

TEST(CordAesGcmSivBoringSslNegativeTest, InvalidKeySizesFail) {
  for (int invalid_size : {0, 1, 15, 17, 24, 31, 33}) {
    EXPECT_THAT(AesGcmSivParameters::Create(invalid_size, Variant::kNoPrefix),
                StatusIs(absl::StatusCode::kInvalidArgument))
        << "Key size: " << invalid_size;
  }
}

TEST(CordAesGcmSivBoringSslNegativeTest, FipsModeDisabled) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "Unimplemented with OpenSSL";
  }
#if defined(BORINGSSL_FIPS) || defined(TINK_USE_ONLY_FIPS)
  GTEST_SKIP() << "Unimplemented with BoringSSL FIPS";
#endif
  if (!internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  absl::StatusOr<AesGcmSivKey> key128 =
      CreateKey(test::HexDecodeOrDie(kKey128Hex));
  ASSERT_THAT(key128, IsOk());
  absl::StatusOr<AesGcmSivKey> key256 =
      CreateKey(test::HexDecodeOrDie(kKey256Hex));
  ASSERT_THAT(key256, IsOk());

  EXPECT_THAT(NewCordAesGcmSivBoringSsl(*key128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(NewCordAesGcmSivBoringSsl(*key256).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(CordAesGcmSivBoringSslNegativeTest, DisabledInBoringSslFipsOrOpenSsl) {
#if defined(OPENSSL_IS_BORINGSSL) && !defined(TINK_USE_ONLY_FIPS) && \
    !defined(BORINGSSL_FIPS)
  GTEST_SKIP() << "Supported in standard BoringSSL";
#else
  absl::StatusOr<AesGcmSivKey> key128 =
      CreateKey(test::HexDecodeOrDie(kKey128Hex));
  ASSERT_THAT(key128, IsOk());
  absl::StatusOr<AesGcmSivKey> key256 =
      CreateKey(test::HexDecodeOrDie(kKey256Hex));
  ASSERT_THAT(key256, IsOk());

  EXPECT_THAT(NewCordAesGcmSivBoringSsl(*key128).status(),
              StatusIs(absl::StatusCode::kUnimplemented));
  EXPECT_THAT(NewCordAesGcmSivBoringSsl(*key256).status(),
              StatusIs(absl::StatusCode::kUnimplemented));
#endif
}

TEST_P(CordAesGcmSivBoringSslWycheproofTest, DecryptTestVectors) {
  const WycheproofTestVector& tc = GetParam();
  int iv_size = tc.nonce.size();
  int tag_size = tc.tag.size();
  int key_size = tc.key.size();

  // CordAesGcmSivBoringSsl supports 12-byte IVs, 16-byte tag, and 16 or 32 byte
  // keys.
  if (iv_size != kIvSizeInBytes || tag_size != kTagSizeInBytes ||
      (key_size != 16 && key_size != 32)) {
    GTEST_SKIP() << "Unsupported test vector parameters";
  }

  absl::StatusOr<AesGcmSivKey> key =
      CreateKey(tc.key, Variant::kNoPrefix, /*id_requirement=*/std::nullopt);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<CordAead>> aead =
      NewCordAesGcmSivBoringSsl(*key);
  ASSERT_THAT(aead, IsOk());

  absl::Cord ct_cord(tc.nonce + tc.ct + tc.tag);
  absl::Cord aad_cord(tc.aad);
  absl::StatusOr<absl::Cord> result = (*aead)->Decrypt(ct_cord, aad_cord);

  if (result.ok()) {
    EXPECT_NE(tc.expected, "invalid")
        << "Decrypted invalid ciphertext tcId: " << tc.id;
    EXPECT_EQ(result->Flatten(), tc.msg)
        << "Incorrect decryption for tcId: " << tc.id;
  } else {
    EXPECT_THAT(tc.expected, Not(testing::AnyOf(Eq("valid"), Eq("acceptable"))))
        << "Could not decrypt test with tcId: " << tc.id
        << " iv_size: " << iv_size << " tag_size: " << tag_size
        << " key_size: " << key_size << " error: " << GetError();
  }
}

INSTANTIATE_TEST_SUITE_P(
    WycheproofTests, CordAesGcmSivBoringSslWycheproofTest,
    ValuesIn(ReadWycheproofTestVectors("aes_gcm_siv_test.json")));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
