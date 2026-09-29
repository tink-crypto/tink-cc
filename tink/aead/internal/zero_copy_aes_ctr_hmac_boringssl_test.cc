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

#include "tink/aead/internal/zero_copy_aes_ctr_hmac_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
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
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead.h"
#include "tink/aead/aes_ctr_hmac_aead_key.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/aes_ctr_hmac_aead_test_vectors.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/mac.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/subtle/aes_ctr_boringssl.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/encrypt_then_authenticate.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/subtle/ind_cpa_cipher.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::Ne;
using ::testing::StartsWith;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

constexpr absl::string_view kAesKey128Hex = "000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kHmacKeyHex =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr absl::string_view kMessage = "Some data to encrypt.";
constexpr absl::string_view kAssociatedData = "Some data to authenticate.";
constexpr int kIvSizeInBytes = 12;
constexpr int kTagSizeInBytes = 16;

absl::StatusOr<AesCtrHmacAeadKey> CreateTestKey(
    absl::string_view aes_key_bytes, int iv_size,
    absl::string_view hmac_key_bytes,
    AesCtrHmacAeadParameters::HashType hash_type, int tag_size,
    AesCtrHmacAeadParameters::Variant variant =
        AesCtrHmacAeadParameters::Variant::kNoPrefix,
    std::optional<int> id_requirement = std::nullopt) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(aes_key_bytes.size())
          .SetIvSizeInBytes(iv_size)
          .SetHmacKeySizeInBytes(hmac_key_bytes.size())
          .SetTagSizeInBytes(tag_size)
          .SetHashType(hash_type)
          .SetVariant(variant)
          .Build();
  if (!parameters.ok()) {
    return parameters.status();
  }
  AesCtrHmacAeadKey::Builder builder;
  builder.SetParameters(*parameters)
      .SetAesKeyBytes(
          RestrictedData(aes_key_bytes, InsecureSecretKeyAccess::Get()))
      .SetHmacKeyBytes(
          RestrictedData(hmac_key_bytes, InsecureSecretKeyAccess::Get()));
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(id_requirement);
  }
  return builder.Build(GetPartialKeyAccess());
}

class ZeroCopyAesCtrHmacBoringSslTest : public testing::Test {
 protected:
  void SetUp() override {
    std::string aes_key = test::HexDecodeOrDie(kAesKey128Hex);
    std::string hmac_key = test::HexDecodeOrDie(kHmacKeyHex);
    absl::StatusOr<AesCtrHmacAeadKey> key = CreateTestKey(
        aes_key, kIvSizeInBytes, hmac_key,
        AesCtrHmacAeadParameters::HashType::kSha256, kTagSizeInBytes);
    ASSERT_THAT(key, IsOk());
    absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
        ZeroCopyAesCtrHmacBoringSsl::New(*key);
    ASSERT_THAT(cipher, IsOk());
    cipher_ = std::move(*cipher);
  }

  std::unique_ptr<ZeroCopyAead> cipher_;
};

TEST_F(ZeroCopyAesCtrHmacBoringSslTest,
       MaxDecryptionSizeOfMaxEncryptionSizeOfMessageIsMessageSize) {
  EXPECT_EQ(
      static_cast<int64_t>(kMessage.size()),
      cipher_->MaxDecryptionSize(cipher_->MaxEncryptionSize(kMessage.size())));
  EXPECT_EQ(cipher_->MaxDecryptionSize(std::numeric_limits<int64_t>::min()), 0);
  EXPECT_EQ(cipher_->MaxDecryptionSize(-1), 0);
  EXPECT_EQ(cipher_->MaxDecryptionSize(0), 0);
  EXPECT_EQ(cipher_->MaxDecryptionSize(kIvSizeInBytes + kTagSizeInBytes - 1),
            0);
  EXPECT_EQ(cipher_->MaxDecryptionSize(kIvSizeInBytes + kTagSizeInBytes), 0);
  EXPECT_EQ(cipher_->MaxDecryptionSize(kIvSizeInBytes + kTagSizeInBytes + 1),
            1);
}

TEST_F(ZeroCopyAesCtrHmacBoringSslTest,
       DecryptEmptyPlaintextWithEmptySpanSucceeds) {
  std::string ciphertext(cipher_->MaxEncryptionSize(0), '\0');
  ASSERT_THAT(cipher_->Encrypt("", kAssociatedData, absl::MakeSpan(ciphertext)),
              IsOkAndHolds(ciphertext.size()));
  EXPECT_THAT(cipher_->Decrypt(ciphertext, kAssociatedData, absl::Span<char>()),
              IsOkAndHolds(0));
}

TEST_F(ZeroCopyAesCtrHmacBoringSslTest, EncryptDecryptVariousSizesAndPrefixes) {
  std::string aes_key = test::HexDecodeOrDie(kAesKey128Hex);
  std::string hmac_key = test::HexDecodeOrDie(kHmacKeyHex);

  struct TestCase {
    AesCtrHmacAeadParameters::Variant variant;
    std::optional<int> id_requirement;
    std::string expected_prefix;
  };
  const std::vector<TestCase> test_cases = {
      {AesCtrHmacAeadParameters::Variant::kNoPrefix, std::nullopt, ""},
      {AesCtrHmacAeadParameters::Variant::kTink, 0x01020304,
       "\x01\x01\x02\x03\x04"},
      {AesCtrHmacAeadParameters::Variant::kCrunchy, 0x01020304,
       std::string("\x00\x01\x02\x03\x04", 5)},
  };

  for (const auto& tc : test_cases) {
    absl::StatusOr<AesCtrHmacAeadKey> key =
        CreateTestKey(aes_key, kIvSizeInBytes, hmac_key,
                      AesCtrHmacAeadParameters::HashType::kSha256,
                      kTagSizeInBytes, tc.variant, tc.id_requirement);
    ASSERT_THAT(key, IsOk());
    absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
        ZeroCopyAesCtrHmacBoringSsl::New(*key);
    ASSERT_THAT(cipher, IsOk());

    for (size_t pt_size : {0, 1, 15, 16, 17, 1024, 16384}) {
      std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
      std::string aad = subtle::Random::GetRandomBytes(23);

      std::string ciphertext;
      subtle::ResizeStringUninitialized(
          &ciphertext, (*cipher)->MaxEncryptionSize(plaintext.size()));
      absl::StatusOr<int64_t> ct_size =
          (*cipher)->Encrypt(plaintext, aad, absl::MakeSpan(ciphertext));
      ASSERT_THAT(ct_size, IsOk());
      EXPECT_EQ(*ct_size, static_cast<int64_t>(tc.expected_prefix.size() +
                                               kIvSizeInBytes + pt_size +
                                               kTagSizeInBytes));
      ciphertext.resize(*ct_size);
      if (!tc.expected_prefix.empty()) {
        EXPECT_THAT(ciphertext, StartsWith(tc.expected_prefix));
      }

      std::string decrypted;
      subtle::ResizeStringUninitialized(
          &decrypted, (*cipher)->MaxDecryptionSize(ciphertext.size()));
      absl::StatusOr<int64_t> dec_size =
          (*cipher)->Decrypt(ciphertext, aad, absl::MakeSpan(decrypted));
      ASSERT_THAT(dec_size, IsOkAndHolds(pt_size));
      decrypted.resize(*dec_size);
      EXPECT_EQ(decrypted, plaintext);
    }
  }
}

TEST_F(ZeroCopyAesCtrHmacBoringSslTest, EncryptProducesDistinctRandomIvs) {
  std::string aes_key = test::HexDecodeOrDie(kAesKey128Hex);
  std::string hmac_key = test::HexDecodeOrDie(kHmacKeyHex);
  constexpr absl::string_view kPrefix = "\x01\xaa\xbb\xcc\xdd";

  absl::StatusOr<AesCtrHmacAeadKey> key = CreateTestKey(
      aes_key, kIvSizeInBytes, hmac_key,
      AesCtrHmacAeadParameters::HashType::kSha256, kTagSizeInBytes,
      AesCtrHmacAeadParameters::Variant::kTink, 0xaabbccdd);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ZeroCopyAesCtrHmacBoringSsl::New(*key);
  ASSERT_THAT(cipher, IsOk());

  std::string ct1((*cipher)->MaxEncryptionSize(kMessage.size()), '\0');
  std::string ct2((*cipher)->MaxEncryptionSize(kMessage.size()), '\0');
  ASSERT_THAT(
      (*cipher)->Encrypt(kMessage, kAssociatedData, absl::MakeSpan(ct1)),
      IsOk());
  ASSERT_THAT(
      (*cipher)->Encrypt(kMessage, kAssociatedData, absl::MakeSpan(ct2)),
      IsOk());

  EXPECT_THAT(ct1, StartsWith(kPrefix));
  EXPECT_THAT(ct2, StartsWith(kPrefix));

  absl::string_view iv1 =
      absl::string_view(ct1).substr(kPrefix.size(), kIvSizeInBytes);
  absl::string_view iv2 =
      absl::string_view(ct2).substr(kPrefix.size(), kIvSizeInBytes);
  EXPECT_THAT(iv1, Ne(iv2));
  EXPECT_THAT(ct1, Ne(ct2));
}

TEST_F(ZeroCopyAesCtrHmacBoringSslTest, TamperingFailsAndZeroesOutputBuffer) {
  std::string aes_key = test::HexDecodeOrDie(kAesKey128Hex);
  std::string hmac_key = test::HexDecodeOrDie(kHmacKeyHex);
  constexpr absl::string_view kPrefix = "\x01\x11\x22\x33\x44";

  absl::StatusOr<AesCtrHmacAeadKey> key = CreateTestKey(
      aes_key, kIvSizeInBytes, hmac_key,
      AesCtrHmacAeadParameters::HashType::kSha256, kTagSizeInBytes,
      AesCtrHmacAeadParameters::Variant::kTink, 0x11223344);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ZeroCopyAesCtrHmacBoringSsl::New(*key);
  ASSERT_THAT(cipher, IsOk());

  std::string ct((*cipher)->MaxEncryptionSize(kMessage.size()), '\0');
  ASSERT_THAT((*cipher)->Encrypt(kMessage, kAssociatedData, absl::MakeSpan(ct)),
              IsOk());

  // Flip every byte position in ciphertext (prefix, IV, raw ciphertext, tag).
  for (size_t i = 0; i < ct.size(); ++i) {
    std::string corrupted_ct = ct;
    corrupted_ct[i] ^= 0x01;
    std::string out_buf(kMessage.size(), 'X');
    EXPECT_THAT(
        (*cipher)
            ->Decrypt(corrupted_ct, kAssociatedData, absl::MakeSpan(out_buf))
            .status(),
        StatusIs(absl::StatusCode::kInvalidArgument));
    // When tag verification fails (any byte after prefix), output buffer must
    // be zeroed.
    if (i >= kPrefix.size()) {
      EXPECT_EQ(out_buf, std::string(kMessage.size(), '\0'));
    }
  }

  // Flip AAD byte.
  std::string corrupted_aad(kAssociatedData);
  corrupted_aad[0] ^= 0x01;
  std::string out_buf(kMessage.size(), 'X');
  EXPECT_THAT(
      (*cipher)->Decrypt(ct, corrupted_aad, absl::MakeSpan(out_buf)).status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_EQ(out_buf, std::string(kMessage.size(), '\0'));

  // 0-byte plaintext tampering.
  std::string empty_ct((*cipher)->MaxEncryptionSize(0), '\0');
  ASSERT_THAT((*cipher)->Encrypt("", kAssociatedData, absl::MakeSpan(empty_ct)),
              IsOkAndHolds(empty_ct.size()));
  for (size_t i = 0; i < empty_ct.size(); ++i) {
    std::string corrupted_empty_ct = empty_ct;
    corrupted_empty_ct[i] ^= 0x01;
    std::string empty_out_buf;
    EXPECT_THAT((*cipher)
                    ->Decrypt(corrupted_empty_ct, kAssociatedData,
                              absl::MakeSpan(empty_out_buf))
                    .status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }

  // Truncated ciphertext fails.
  EXPECT_THAT((*cipher)
                  ->Decrypt(absl::string_view(ct).substr(
                                0, kPrefix.size() + kIvSizeInBytes +
                                       kTagSizeInBytes - 1),
                            kAssociatedData, absl::MakeSpan(out_buf))
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ZeroCopyAesCtrHmacBoringSslTest, OversizedOutputBuffersSucceed) {
  const int64_t expected_ct_size = cipher_->MaxEncryptionSize(kMessage.size());
  std::string ct_buffer(expected_ct_size + 64, 'Z');
  absl::StatusOr<int64_t> ct_size =
      cipher_->Encrypt(kMessage, kAssociatedData, absl::MakeSpan(ct_buffer));
  ASSERT_THAT(ct_size, IsOkAndHolds(expected_ct_size));

  absl::string_view actual_ct(ct_buffer.data(), *ct_size);
  const int64_t expected_pt_size = cipher_->MaxDecryptionSize(actual_ct.size());
  ASSERT_EQ(expected_pt_size, static_cast<int64_t>(kMessage.size()));
  std::string pt_buffer(expected_pt_size + 64, 'Z');
  absl::StatusOr<int64_t> pt_size =
      cipher_->Decrypt(actual_ct, kAssociatedData, absl::MakeSpan(pt_buffer));
  ASSERT_THAT(pt_size, IsOkAndHolds(kMessage.size()));
  EXPECT_EQ(absl::string_view(pt_buffer.data(), *pt_size), kMessage);
}

TEST_F(ZeroCopyAesCtrHmacBoringSslTest, EncryptBufferTooSmall) {
  std::string ciphertext(cipher_->MaxEncryptionSize(kMessage.size()) - 1, '\0');
  EXPECT_THAT(
      cipher_->Encrypt(kMessage, kAssociatedData, absl::MakeSpan(ciphertext))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ZeroCopyAesCtrHmacBoringSslTest, DecryptBufferTooSmall) {
  std::string ciphertext(cipher_->MaxEncryptionSize(kMessage.size()), '\0');
  ASSERT_THAT(
      cipher_->Encrypt(kMessage, kAssociatedData, absl::MakeSpan(ciphertext)),
      IsOk());

  std::string plaintext(kMessage.size() - 1, '\0');
  EXPECT_THAT(
      cipher_->Decrypt(ciphertext, kAssociatedData, absl::MakeSpan(plaintext))
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(ZeroCopyAesCtrHmacBoringSslTest, EncryptOverlappingBuffersFails) {
  std::string buffer(256, 'A');
  absl::string_view pt(buffer.data(), kMessage.size());
  absl::Span<char> ct_span = absl::MakeSpan(buffer).subspan(10);
  EXPECT_THAT(cipher_->Encrypt(pt, kAssociatedData, ct_span).status(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(ZeroCopyAesCtrHmacBoringSslTest, DecryptOverlappingBuffersFails) {
  std::string ciphertext(cipher_->MaxEncryptionSize(kMessage.size()), '\0');
  ASSERT_THAT(
      cipher_->Encrypt(kMessage, kAssociatedData, absl::MakeSpan(ciphertext)),
      IsOk());

  std::string buffer(256, '\0');
  std::memcpy(buffer.data() + 5, ciphertext.data(), ciphertext.size());
  absl::string_view ct_view(buffer.data() + 5, ciphertext.size());
  absl::Span<char> pt_span = absl::MakeSpan(buffer).subspan(0, kMessage.size());
  EXPECT_THAT(cipher_->Decrypt(ct_view, kAssociatedData, pt_span).status(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

struct AesCtrHmacEquivalenceTestParams {
  int aes_key_size;
  int iv_size;
  AesCtrHmacAeadParameters::HashType hash_type;
  subtle::HashType subtle_hash_type;
  int tag_size;
};

class ZeroCopyAesCtrHmacBoringSslEquivalenceTest
    : public testing::TestWithParam<AesCtrHmacEquivalenceTestParams> {};

TEST_P(ZeroCopyAesCtrHmacBoringSslEquivalenceTest,
       BidirectionalEquivalenceWithEncryptThenAuthenticate) {
  const AesCtrHmacEquivalenceTestParams& params = GetParam();
  std::string aes_key_str = subtle::Random::GetRandomBytes(params.aes_key_size);
  std::string hmac_key_str = subtle::Random::GetRandomBytes(32);
  SecretData aes_key = util::SecretDataFromStringView(aes_key_str);
  SecretData hmac_key = util::SecretDataFromStringView(hmac_key_str);

  absl::StatusOr<AesCtrHmacAeadKey> key =
      CreateTestKey(aes_key_str, params.iv_size, hmac_key_str, params.hash_type,
                    params.tag_size);
  ASSERT_THAT(key, IsOk());
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> zc_aead =
      ZeroCopyAesCtrHmacBoringSsl::New(*key);
  ASSERT_THAT(zc_aead, IsOk());

  absl::StatusOr<std::unique_ptr<subtle::IndCpaCipher>> ind_cpa =
      subtle::AesCtrBoringSsl::New(aes_key, params.iv_size);
  ASSERT_THAT(ind_cpa, IsOk());
  absl::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
      params.subtle_hash_type, params.tag_size, hmac_key);
  ASSERT_THAT(mac, IsOk());
  absl::StatusOr<std::unique_ptr<Aead>> eta_aead =
      subtle::EncryptThenAuthenticate::New(*std::move(ind_cpa), *std::move(mac),
                                           params.tag_size);
  ASSERT_THAT(eta_aead, IsOk());

  for (size_t pt_size : {0, 1, 16, 63, 256}) {
    std::string pt = subtle::Random::GetRandomBytes(pt_size);
    std::string aad = subtle::Random::GetRandomBytes(19);

    // Direction 1: ZeroCopy Encrypt -> EncryptThenAuthenticate Decrypt
    std::string zc_ct((*zc_aead)->MaxEncryptionSize(pt.size()), '\0');
    ASSERT_THAT((*zc_aead)->Encrypt(pt, aad, absl::MakeSpan(zc_ct)),
                IsOkAndHolds(zc_ct.size()));
    EXPECT_THAT((*eta_aead)->Decrypt(zc_ct, aad), IsOkAndHolds(pt));

    // Direction 2: EncryptThenAuthenticate Encrypt -> ZeroCopy Decrypt
    absl::StatusOr<std::string> eta_ct = (*eta_aead)->Encrypt(pt, aad);
    ASSERT_THAT(eta_ct, IsOk());
    std::string zc_pt((*zc_aead)->MaxDecryptionSize(eta_ct->size()), '\0');
    ASSERT_THAT((*zc_aead)->Decrypt(*eta_ct, aad, absl::MakeSpan(zc_pt)),
                IsOkAndHolds(pt.size()));
    EXPECT_EQ(zc_pt, pt);
  }
}

std::vector<AesCtrHmacEquivalenceTestParams> GetEquivalenceTestParams() {
  std::vector<AesCtrHmacEquivalenceTestParams> params;
  struct HashConfig {
    AesCtrHmacAeadParameters::HashType hash_type;
    subtle::HashType subtle_hash_type;
    std::vector<int> tag_sizes;
  };
  const std::vector<HashConfig> hash_configs = {
      {AesCtrHmacAeadParameters::HashType::kSha1,
       subtle::HashType::SHA1,
       {10, 20}},
      {AesCtrHmacAeadParameters::HashType::kSha224,
       subtle::HashType::SHA224,
       {10, 28}},
      {AesCtrHmacAeadParameters::HashType::kSha256,
       subtle::HashType::SHA256,
       {10, 16, 32}},
      {AesCtrHmacAeadParameters::HashType::kSha384,
       subtle::HashType::SHA384,
       {10, 24, 48}},
      {AesCtrHmacAeadParameters::HashType::kSha512,
       subtle::HashType::SHA512,
       {10, 32, 64}},
  };

  for (int aes_key_size : {16, 32}) {
    for (int iv_size : {12, 13, 14, 15, 16}) {
      for (const auto& hc : hash_configs) {
        for (int tag_size : hc.tag_sizes) {
          params.push_back({aes_key_size, iv_size, hc.hash_type,
                            hc.subtle_hash_type, tag_size});
        }
      }
    }
  }
  return params;
}

INSTANTIATE_TEST_SUITE_P(ZeroCopyAesCtrHmacBoringSslEquivalenceTests,
                         ZeroCopyAesCtrHmacBoringSslEquivalenceTest,
                         testing::ValuesIn(GetEquivalenceTestParams()));

TEST(ZeroCopyAesCtrHmacBoringSslValidationTest, InvalidParametersFail) {
  std::string valid_aes_16 = subtle::Random::GetRandomBytes(16);
  std::string valid_hmac_32 = subtle::Random::GetRandomBytes(32);

  // 24-byte AES key is allowed by AesCtrHmacAeadParameters, but rejected by
  // BoringSSL ZeroCopyAesCtrHmacBoringSsl::New.
  absl::StatusOr<AesCtrHmacAeadKey> key_24 =
      CreateTestKey(subtle::Random::GetRandomBytes(24), 12, valid_hmac_32,
                    AesCtrHmacAeadParameters::HashType::kSha256, 16);
  ASSERT_THAT(key_24, IsOk());
  EXPECT_THAT(ZeroCopyAesCtrHmacBoringSsl::New(*key_24).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Invalid IV size (< 12 or > 16) fails in AesCtrHmacAeadParameters::Builder
  EXPECT_THAT(CreateTestKey(valid_aes_16, 11, valid_hmac_32,
                            AesCtrHmacAeadParameters::HashType::kSha256, 16)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(CreateTestKey(valid_aes_16, 17, valid_hmac_32,
                            AesCtrHmacAeadParameters::HashType::kSha256, 16)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Invalid HMAC key size (< 16) fails in AesCtrHmacAeadParameters::Builder
  EXPECT_THAT(
      CreateTestKey(valid_aes_16, 12, subtle::Random::GetRandomBytes(15),
                    AesCtrHmacAeadParameters::HashType::kSha256, 16)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));

  // Invalid tag size (< 10 or > digest size) fails in
  // AesCtrHmacAeadParameters::Builder
  EXPECT_THAT(CreateTestKey(valid_aes_16, 12, valid_hmac_32,
                            AesCtrHmacAeadParameters::HashType::kSha256, 9)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(CreateTestKey(valid_aes_16, 12, valid_hmac_32,
                            AesCtrHmacAeadParameters::HashType::kSha256, 33)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

using ZeroCopyAesCtrHmacBoringSslTestVectorTest = TestWithParam<AeadTestVector>;

TEST_P(ZeroCopyAesCtrHmacBoringSslTestVectorTest, DecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const AesCtrHmacAeadKey& key =
      dynamic_cast<const AesCtrHmacAeadKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ZeroCopyAesCtrHmacBoringSsl::New(key);
  if (key.GetParameters().GetAesKeySizeInBytes() == 24) {
    EXPECT_THAT(cipher.status(), StatusIs(absl::StatusCode::kInvalidArgument));
    return;
  }
  ASSERT_THAT(cipher, IsOk());

  std::string plaintext;
  subtle::ResizeStringUninitialized(
      &plaintext, (*cipher)->MaxDecryptionSize(test_vector.ciphertext.size()));
  absl::StatusOr<int64_t> plaintext_size =
      (*cipher)->Decrypt(test_vector.ciphertext, test_vector.associated_data,
                         absl::MakeSpan(plaintext));
  ASSERT_THAT(plaintext_size, IsOkAndHolds(test_vector.plaintext.size()));
  EXPECT_EQ(plaintext, test_vector.plaintext);
}

TEST_P(ZeroCopyAesCtrHmacBoringSslTestVectorTest, EncryptDecryptTestVectors) {
  const AeadTestVector& test_vector = GetParam();
  const AesCtrHmacAeadKey& key =
      dynamic_cast<const AesCtrHmacAeadKey&>(*test_vector.aead_key);
  absl::StatusOr<std::unique_ptr<ZeroCopyAead>> cipher =
      ZeroCopyAesCtrHmacBoringSsl::New(key);
  if (key.GetParameters().GetAesKeySizeInBytes() == 24) {
    EXPECT_THAT(cipher.status(), StatusIs(absl::StatusCode::kInvalidArgument));
    return;
  }
  ASSERT_THAT(cipher, IsOk());

  std::string ciphertext;
  subtle::ResizeStringUninitialized(
      &ciphertext, (*cipher)->MaxEncryptionSize(test_vector.plaintext.size()));
  absl::StatusOr<int64_t> ciphertext_size =
      (*cipher)->Encrypt(test_vector.plaintext, test_vector.associated_data,
                         absl::MakeSpan(ciphertext));
  ASSERT_THAT(ciphertext_size, IsOkAndHolds(test_vector.ciphertext.size()));
  if (!key.GetOutputPrefix().empty()) {
    EXPECT_THAT(ciphertext, StartsWith(key.GetOutputPrefix()));
  }

  std::string plaintext;
  subtle::ResizeStringUninitialized(
      &plaintext, (*cipher)->MaxDecryptionSize(ciphertext.size()));
  absl::StatusOr<int64_t> plaintext_size = (*cipher)->Decrypt(
      ciphertext, test_vector.associated_data, absl::MakeSpan(plaintext));
  ASSERT_THAT(plaintext_size, IsOkAndHolds(test_vector.plaintext.size()));
  EXPECT_EQ(plaintext, test_vector.plaintext);
}

INSTANTIATE_TEST_SUITE_P(ZeroCopyAesCtrHmacBoringSslTestVectorTests,
                         ZeroCopyAesCtrHmacBoringSslTestVectorTest,
                         ValuesIn(CreateAesCtrHmacAeadTestVectors()));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
