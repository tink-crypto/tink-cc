// Copyright 2017 Google Inc.
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

#include "tink/subtle/aes_cmac_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/config/tink_fips.h"
#include "tink/mac.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Not;
using ::testing::SizeIs;

constexpr uint32_t kTagSize = 16;
constexpr uint32_t kSmallTagSize = 10;

constexpr absl::string_view kKey256Hex =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

constexpr absl::string_view kMessage = "Some data to test.";

TEST(AesCmacBoringSslTest, Basic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  SecretData key =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKey256Hex));
  absl::StatusOr<std::unique_ptr<Mac>> cmac =
      AesCmacBoringSsl::New(key, kTagSize);
  ASSERT_THAT(cmac, IsOk());
  {  // Test with some example data.
    absl::StatusOr<std::string> tag = (*cmac)->ComputeMac(kMessage);
    EXPECT_THAT(tag, IsOk());
    EXPECT_THAT(*tag, SizeIs(kTagSize));
    EXPECT_THAT((*cmac)->VerifyMac(*tag, kMessage), IsOk())
        << "tag:" << test::HexEncode(*tag);
  }
  {  // Test with empty example data.
    absl::string_view data;
    absl::StatusOr<std::string> tag = (*cmac)->ComputeMac(data);
    EXPECT_THAT(tag, IsOk());
    EXPECT_THAT(*tag, SizeIs(kTagSize));
    EXPECT_THAT((*cmac)->VerifyMac(*tag, data), IsOk())
        << "tag:" << test::HexEncode(*tag);
  }
}

TEST(AesCmacBoringSslTest, Modification) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  SecretData key =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKey256Hex));
  absl::StatusOr<std::unique_ptr<Mac>> cmac =
      AesCmacBoringSsl::New(key, kTagSize);
  ASSERT_THAT(cmac, IsOk());
  absl::StatusOr<std::string> tag = (*cmac)->ComputeMac(kMessage);
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT((*cmac)->VerifyMac(*tag, kMessage), IsOk());
  const size_t num_bits = tag->size() * 8;
  for (size_t i = 0; i < num_bits; i++) {
    std::string modified_tag = *tag;
    modified_tag[i / 8] ^= 1 << (i % 8);
    EXPECT_THAT((*cmac)->VerifyMac(modified_tag, kMessage), Not(IsOk()))
        << "tag:" << test::HexEncode(*tag)
        << " modified:" << test::HexEncode(modified_tag);
  }
}

TEST(AesCmacBoringSslTest, Truncation) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  SecretData key =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKey256Hex));
  absl::StatusOr<std::unique_ptr<Mac>> cmac =
      AesCmacBoringSsl::New(key, kTagSize);
  ASSERT_THAT(cmac, IsOk());
  absl::StatusOr<std::string> tag = (*cmac)->ComputeMac(kMessage);
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT((*cmac)->VerifyMac(*tag, kMessage), IsOk());
  for (size_t i = 0; i < tag->size(); i++) {
    std::string modified_tag(*tag, 0, i);
    EXPECT_FALSE((*cmac)->VerifyMac(modified_tag, kMessage).ok())
        << "tag:" << test::HexEncode(*tag)
        << " modified:" << test::HexEncode(modified_tag);
  }
}

TEST(AesCmacBoringSslTest, BasicSmallTag) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  SecretData key =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKey256Hex));
  absl::StatusOr<std::unique_ptr<Mac>> cmac =
      AesCmacBoringSsl::New(key, kSmallTagSize);
  EXPECT_THAT(cmac, IsOk());
  {  // Test with some example data.
    std::string data = "Some data to test.";
    absl::StatusOr<std::string> tag = (*cmac)->ComputeMac(data);
    EXPECT_THAT(tag, IsOk());
    EXPECT_EQ(kSmallTagSize, tag->size());
    EXPECT_THAT((*cmac)->VerifyMac(*tag, data), IsOk())
        << "tag:" << test::HexEncode(*tag);
  }
  {  // Test with empty example data.
    absl::string_view data;
    absl::StatusOr<std::string> tag = (*cmac)->ComputeMac(data);
    EXPECT_THAT(tag, IsOk());
    EXPECT_EQ(kSmallTagSize, tag->size());
    EXPECT_THAT((*cmac)->VerifyMac(*tag, data), IsOk())
        << "tag:" << test::HexEncode(*tag);
  }
}

TEST(AesCmacBoringSslTest, ModificationSmallTag) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  SecretData key =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKey256Hex));
  absl::StatusOr<std::unique_ptr<Mac>> cmac =
      AesCmacBoringSsl::New(key, kSmallTagSize);
  ASSERT_THAT(cmac, IsOk());
  absl::StatusOr<std::string> tag = (*cmac)->ComputeMac(kMessage);
  ASSERT_THAT(tag, IsOk());
  auto status = (*cmac)->VerifyMac(*tag, kMessage);
  EXPECT_THAT((*cmac)->VerifyMac(*tag, kMessage), IsOk());
  size_t num_bits = tag->size() * 8;
  for (size_t i = 0; i < num_bits; i++) {
    std::string modified_tag = *tag;
    modified_tag[i / 8] ^= 1 << (i % 8);
    EXPECT_THAT((*cmac)->VerifyMac(modified_tag, kMessage), Not(IsOk()))
        << "tag:" << test::HexEncode(*tag)
        << " modified:" << test::HexEncode(modified_tag);
  }
}

TEST(AesCmacBoringSslTest, TruncationOrAdditionSmallTag) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  SecretData key =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKey256Hex));
  absl::StatusOr<std::unique_ptr<Mac>> cmac =
      AesCmacBoringSsl::New(key, kSmallTagSize);
  ASSERT_THAT(cmac, IsOk());
  absl::StatusOr<std::string> tag = (*cmac)->ComputeMac(kMessage);
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT((*cmac)->VerifyMac(*tag, kMessage), IsOk());
  for (size_t i = 0; i < kSmallTagSize; i++) {
    std::string modified_tag(*tag, 0, i);
    EXPECT_THAT((*cmac)->VerifyMac(modified_tag, kMessage), Not(IsOk()))
        << "tag:" << test::HexEncode(*tag)
        << " modified:" << test::HexEncode(modified_tag);
  }
  for (size_t i = kSmallTagSize + 1; i < kTagSize; i++) {
    std::string modified_tag(*tag + std::string(i - kSmallTagSize, 'x'));
    EXPECT_THAT((*cmac)->VerifyMac(modified_tag, kMessage), Not(IsOk()))
        << "tag:" << test::HexEncode(*tag)
        << " modified:" << test::HexEncode(modified_tag);
  }
}

TEST(AesCmacBoringSslTest, InvalidKeySizes) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  for (int keysize = 0; keysize < 65; keysize++) {
    SecretData key(keysize, 'x');
    absl::StatusOr<std::unique_ptr<Mac>> cmac =
        AesCmacBoringSsl::New(key, kTagSize);
    if (keysize == 16 || keysize == 32) {
      EXPECT_THAT(cmac, IsOk());
    } else {
      EXPECT_THAT(cmac, Not(IsOk()));
    }
  }
}

TEST(AesCmacBoringSslTest, InvalidTagSizes) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  for (int tagsize = 0; tagsize < 65; tagsize++) {
    SecretData key(32, 'x');
    absl::StatusOr<std::unique_ptr<Mac>> cmac =
        AesCmacBoringSsl::New(key, tagsize);
    if (tagsize <= 16) {
      EXPECT_THAT(cmac, IsOk());
    } else {
      EXPECT_THAT(cmac, Not(IsOk()));
    }
  }
}

class AesCmacBoringSslTestVectorTest
    : public ::testing::TestWithParam<std::pair<int, std::string>> {
 public:
  // Utility to simplify testing with test vectors. Parameters are in
  // hexadecimal.
  void ExpectCmacVerifyHex(absl::string_view key_hex, absl::string_view tag_hex,
                           absl::string_view data_hex) {
    SecretData key =
        util::SecretDataFromStringView(test::HexDecodeOrDie(key_hex));
    std::string tag = test::HexDecodeOrDie(tag_hex);
    std::string data = test::HexDecodeOrDie(data_hex);
    absl::StatusOr<std::unique_ptr<Mac>> cmac =
        AesCmacBoringSsl::New(key, kTagSize);
    EXPECT_THAT(cmac, IsOk());
    EXPECT_THAT((*cmac)->VerifyMac(tag, data), IsOk());
  }
};

TEST_P(AesCmacBoringSslTestVectorTest, RfcTestVectors) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // Test vectors from RFC 4493.
  std::string key("2b7e151628aed2a6abf7158809cf4f3c");
  std::string data(
      "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46"
      "a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
  ExpectCmacVerifyHex(key, GetParam().second,
                      data.substr(0, 2 * GetParam().first));
}
INSTANTIATE_TEST_SUITE_P(
    RfcTest, AesCmacBoringSslTestVectorTest,
    testing::Values(std::make_pair(0, "bb1d6929e95937287fa37d129b756746"),
                    std::make_pair(16, "070a16b46b4d4144f79bdd9dd04a287c"),
                    std::make_pair(40, "dfa66747de9ae63030ca32611497c827"),
                    std::make_pair(64, "51f0bebf7e3b9d92fc49741779363cfe")));

TEST(AesCmacBoringSslTest, TestFipsOnly) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }

  SecretData key128 = util::SecretDataFromStringView(
      test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  SecretData key256 =
      util::SecretDataFromStringView(test::HexDecodeOrDie(kKey256Hex));

  EXPECT_THAT(subtle::AesCmacBoringSsl::New(key128, kTagSize).status(),
              StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(subtle::AesCmacBoringSsl::New(key256, kTagSize).status(),
              StatusIs(absl::StatusCode::kInternal));
}
}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
