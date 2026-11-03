// Copyright 2017 Google LLC
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

#include "tink/subtle/hmac_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "benchmark/benchmark.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/fips_utils.h"
#include "tink/mac.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::subtle::Random;
using ::testing::Eq;
using ::testing::Not;

class HmacBoringSslTest : public ::testing::Test {
 public:
  // Utility to simplify testing with test vectors.
  // Arguments and result are hexadecimal.
  bool HmacVerifyHex(HashType hash, uint32_t tag_size,
                     const std::string &key_hex, const std::string &tag_hex,
                     const std::string &data_hex) {
    SecretData key =
        util::SecretDataFromStringView(test::HexDecodeOrDie(key_hex));
    std::string tag = test::HexDecodeOrDie(tag_hex);
    std::string data = test::HexDecodeOrDie(data_hex);
    auto hmac_result = HmacBoringSsl::New(hash, tag_size, key);
    EXPECT_THAT(hmac_result, IsOk());
    auto hmac = std::move(hmac_result.value());
    auto result = hmac->VerifyMac(tag, data);
    return result.ok();
  }
};

TEST_F(HmacBoringSslTest, testBasic) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  size_t tag_size = 16;
  auto hmac_result = HmacBoringSsl::New(HashType::SHA1, tag_size, key);
  EXPECT_THAT(hmac_result, IsOk());
  auto hmac = std::move(hmac_result.value());
  { // Test with some example data.
    std::string data = "Some data to test.";
    auto res = hmac->ComputeMac(data);
    EXPECT_THAT(res, IsOk());
    std::string tag = res.value();
    EXPECT_EQ(tag_size, tag.size());
    EXPECT_EQ(tag, test::HexDecodeOrDie("9ccdca5b7fffb690df396e4ac49b9cd4"));
    auto status = hmac->VerifyMac(tag, data);
    EXPECT_THAT(status, IsOk()) << "tag:" << test::HexEncode(tag);
  }
  { // Test with empty example data.
    absl::string_view data;
    auto res = hmac->ComputeMac(data);
    EXPECT_THAT(res, IsOk());
    std::string tag = res.value();
    EXPECT_EQ(tag_size, tag.size());
    EXPECT_EQ(tag, test::HexDecodeOrDie("5433122f77bcf8a4d9b874b4149823ef"));
    auto status = hmac->VerifyMac(tag, data);
    EXPECT_THAT(status, IsOk()) << "tag:" << test::HexEncode(tag);
  }
}

TEST_F(HmacBoringSslTest, testModification) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto hmac_result = HmacBoringSsl::New(HashType::SHA1, 16, key);
  EXPECT_THAT(hmac_result, IsOk());
  auto hmac = std::move(hmac_result.value());
  std::string data = "Some data to test";
  std::string tag = hmac->ComputeMac(data).value();
  auto status = hmac->VerifyMac(tag, data);
  EXPECT_THAT(status, IsOk());
  size_t bits = tag.size() * 8;
  for (size_t i = 0; i < bits; i++) {
    std::string modified_tag = tag;
    modified_tag[i / 8] ^= 1 << (i % 8);
    EXPECT_THAT(hmac->VerifyMac(modified_tag, data), Not(IsOk()))
        << "tag:" << test::HexEncode(tag)
        << " modified:" << test::HexEncode(modified_tag);
  }
}

TEST_F(HmacBoringSslTest, testTruncation) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  SecretData key = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  auto hmac_result = HmacBoringSsl::New(HashType::SHA1, 20, key);
  EXPECT_THAT(hmac_result, IsOk());
  auto hmac = std::move(hmac_result.value());
  std::string data = "Some data to test";
  std::string tag = hmac->ComputeMac(data).value();
  auto status = hmac->VerifyMac(tag, data);
  EXPECT_THAT(status, IsOk());
  for (size_t i = 0; i < tag.size(); i++) {
    std::string modified_tag(tag, 0, i);
    EXPECT_THAT(hmac->VerifyMac(modified_tag, data), Not(IsOk()))
        << "tag:" << test::HexEncode(tag)
        << " modified:" << test::HexEncode(modified_tag);
  }
}

TEST_F(HmacBoringSslTest, testInvalidKeySizes) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  size_t tag_size = 16;

  for (int keysize = 0; keysize < 65; keysize++) {
    SecretData key(keysize, 'x');
    auto hmac_result = HmacBoringSsl::New(HashType::SHA1, tag_size, key);
    if (keysize >= 16) {
      EXPECT_THAT(hmac_result, IsOk());
    } else {
      EXPECT_THAT(hmac_result, Not(IsOk()));
    }
  }
}

TEST_F(HmacBoringSslTest, TestFipsFailWithoutBoringCrypto) {
  if (!internal::IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  SecretData key128 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  SecretData key256 = util::SecretDataFromStringView(test::HexDecodeOrDie(
      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"));

  EXPECT_THAT(subtle::HmacBoringSsl::New(HashType::SHA1, 16, key128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(subtle::HmacBoringSsl::New(HashType::SHA224, 16, key128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(subtle::HmacBoringSsl::New(HashType::SHA256, 16, key128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(subtle::HmacBoringSsl::New(HashType::SHA384, 16, key128).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(subtle::HmacBoringSsl::New(HashType::SHA512, 16, key128).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST_F(HmacBoringSslTest, TagSizeExceedingDigestSizeFails) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  SecretData key(16, 'x');
  EXPECT_THAT(HmacBoringSsl::New(HashType::SHA1, /*tag_size=*/20, key), IsOk());
  EXPECT_THAT(HmacBoringSsl::New(HashType::SHA1, /*tag_size=*/21, key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(HmacBoringSsl::New(HashType::SHA224, /*tag_size=*/28, key),
              IsOk());
  EXPECT_THAT(
      HmacBoringSsl::New(HashType::SHA224, /*tag_size=*/29, key).status(),
      StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(HmacBoringSsl::New(HashType::SHA256, /*tag_size=*/32, key),
              IsOk());
  EXPECT_THAT(
      HmacBoringSsl::New(HashType::SHA256, /*tag_size=*/33, key).status(),
      StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(HmacBoringSsl::New(HashType::SHA384, /*tag_size=*/48, key),
              IsOk());
  EXPECT_THAT(
      HmacBoringSsl::New(HashType::SHA384, /*tag_size=*/49, key).status(),
      StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(HmacBoringSsl::New(HashType::SHA512, /*tag_size=*/64, key),
              IsOk());
  EXPECT_THAT(
      HmacBoringSsl::New(HashType::SHA512, /*tag_size=*/65, key).status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HmacBoringSslTest, UnsupportedHashTypeFails) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  SecretData key(16, 'x');
  EXPECT_THAT(
      HmacBoringSsl::New(HashType::UNKNOWN_HASH, /*tag_size=*/16, key).status(),
      StatusIs(absl::StatusCode::kUnimplemented));
}

TEST_F(HmacBoringSslTest, SupportedHashTypesComputeAndVerifyMac) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test should not run in FIPS mode when BoringCrypto is unavailable.";
  }

  // RFC 2202 / RFC 4231 Test Case 1: 20-byte 0x0b key, "Hi There" message.
  SecretData key = SecretData(
      test::HexDecodeOrDie("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));
  constexpr absl::string_view kMessage = "Hi There";

  absl::StatusOr<std::unique_ptr<Mac>> sha1_mac =
      HmacBoringSsl::New(HashType::SHA1, /*tag_size=*/20, key);
  ASSERT_THAT(sha1_mac, IsOk());
  std::string sha1_tag =
      test::HexDecodeOrDie("b617318655057264e28bc0b6fb378c8ef146be00");
  EXPECT_THAT((*sha1_mac)->ComputeMac(kMessage), IsOkAndHolds(Eq(sha1_tag)));
  EXPECT_THAT((*sha1_mac)->VerifyMac(sha1_tag, kMessage), IsOk());

  absl::StatusOr<std::unique_ptr<Mac>> sha224_mac =
      HmacBoringSsl::New(HashType::SHA224, /*tag_size=*/28, key);
  ASSERT_THAT(sha224_mac, IsOk());
  std::string sha224_tag = test::HexDecodeOrDie(
      "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22");
  EXPECT_THAT((*sha224_mac)->ComputeMac(kMessage),
              IsOkAndHolds(Eq(sha224_tag)));
  EXPECT_THAT((*sha224_mac)->VerifyMac(sha224_tag, kMessage), IsOk());

  absl::StatusOr<std::unique_ptr<Mac>> sha256_mac =
      HmacBoringSsl::New(HashType::SHA256, /*tag_size=*/32, key);
  ASSERT_THAT(sha256_mac, IsOk());
  std::string sha256_tag = test::HexDecodeOrDie(
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  EXPECT_THAT((*sha256_mac)->ComputeMac(kMessage),
              IsOkAndHolds(Eq(sha256_tag)));
  EXPECT_THAT((*sha256_mac)->VerifyMac(sha256_tag, kMessage), IsOk());

  absl::StatusOr<std::unique_ptr<Mac>> sha384_mac =
      HmacBoringSsl::New(HashType::SHA384, /*tag_size=*/48, key);
  ASSERT_THAT(sha384_mac, IsOk());
  std::string sha384_tag = test::HexDecodeOrDie(
      "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59"
      "cfaea9ea9076ede7f4af152e8b2fa9cb6");
  EXPECT_THAT((*sha384_mac)->ComputeMac(kMessage),
              IsOkAndHolds(Eq(sha384_tag)));
  EXPECT_THAT((*sha384_mac)->VerifyMac(sha384_tag, kMessage), IsOk());

  absl::StatusOr<std::unique_ptr<Mac>> sha512_mac =
      HmacBoringSsl::New(HashType::SHA512, /*tag_size=*/64, key);
  ASSERT_THAT(sha512_mac, IsOk());
  std::string sha512_tag = test::HexDecodeOrDie(
      "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
      "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
  EXPECT_THAT((*sha512_mac)->ComputeMac(kMessage),
              IsOkAndHolds(Eq(sha512_tag)));
  EXPECT_THAT((*sha512_mac)->VerifyMac(sha512_tag, kMessage), IsOk());
}
// TODO(bleichen): Stuff to test
//  - Generate test vectors and share with Wycheproof.
//  - Tag size wrong for construction
//  - Tag size wrong during verification
//  - Generate invalid tags with 0s in the middle to catch comparison with
//    strcmp or similar.
//  - Generate invalid tags with equal diffs (e.g. to catch broken constant
//    time comparisons.
//  - wrong size of tag during verification
//  - Hmac key size must not be 0 (see RFC)
//  - Generate test vectors with key sizes larger than the block size of the
//    hash. (HMAC hashes these keys).

void HmacComputeBenchmark(benchmark::State &state, HashType hash,
                          int key_size) {
  absl::StatusOr<std::unique_ptr<Mac>> hmac = HmacBoringSsl::New(
      hash, /*tag_size=*/key_size, Random::GetRandomKeyBytes(key_size));
  ABSL_CHECK_OK(hmac.status());
  std::string data(state.range(0), 'x');
  benchmark::DoNotOptimize(data);
  for (auto s : state) {
    absl::StatusOr<std::string> tag = (*hmac)->ComputeMac(data);
    benchmark::DoNotOptimize(tag);
    ABSL_CHECK_OK(tag.status());
  }
  state.SetBytesProcessed(state.iterations() * state.range(0));
}

void BM_HmacSha256Compute(benchmark::State &state) {
  HmacComputeBenchmark(state, HashType::SHA256,
                       /*key_size=*/32);
}

void BM_HmacSha512Compute(benchmark::State &state) {
  HmacComputeBenchmark(state, HashType::SHA512,
                       /*key_size=*/64);
}

constexpr int64_t kMaxDataSize = 1 << 23;  // 4 MiB

BENCHMARK(BM_HmacSha256Compute)->RangeMultiplier(128)->Range(32, kMaxDataSize);
BENCHMARK(BM_HmacSha512Compute)->RangeMultiplier(128)->Range(32, kMaxDataSize);

void HmacVerifyBenchmark(benchmark::State &state, HashType hash, int key_size) {
  absl::StatusOr<std::unique_ptr<Mac>> hmac = HmacBoringSsl::New(
      hash, /*tag_size=*/key_size, Random::GetRandomKeyBytes(key_size));
  ASSERT_THAT(hmac, IsOk());

  std::string data(state.range(0), 'x');
  absl::StatusOr<std::string> tag = (*hmac)->ComputeMac(data);
  ASSERT_THAT(tag, IsOk());
  absl::Status status;
  for (auto s : state) {
    benchmark::DoNotOptimize(status = (*hmac)->VerifyMac(*tag, data));
    ABSL_CHECK_OK(status);
  }
  state.SetBytesProcessed(state.iterations() * state.range(0));
}

void BM_HmacSha256Verify(benchmark::State &state) {
  HmacVerifyBenchmark(state, HashType::SHA256, /*key_size=*/32);
}

void BM_HmacSha512Verify(benchmark::State &state) {
  HmacVerifyBenchmark(state, HashType::SHA512, /*key_size=*/64);
}

BENCHMARK(BM_HmacSha256Verify)->RangeMultiplier(128)->Range(32, kMaxDataSize);
BENCHMARK(BM_HmacSha512Verify)->RangeMultiplier(128)->Range(32, kMaxDataSize);

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto

