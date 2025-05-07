// Copyright 2020 Google LLC
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

#include "tink/mac/internal/stateful_cmac_boringssl.h"

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/testing/wycheproof_util.h"
#include "tink/mac/internal/stateful_mac.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

constexpr size_t kTagSize = 16;
constexpr size_t kSmallTagSize = 10;

constexpr absl::string_view kKeyHex = "000102030405060708090a0b0c0d0e0f";
constexpr absl::string_view kData = "Some data to test.";
constexpr absl::string_view kCmacOnEmptyInputRegularTagSizeHex =
    "97dd6e5a882cbd564c39ae7d1c5a31aa";
constexpr absl::string_view kCmacOnEmptyInputSmallTagSizeHex =
    "97dd6e5a882cbd564c39";
constexpr absl::string_view kCmacOnDataRegularTagSizeHex =
    "c856e183e8dee9bb99402d54c34f3222";
constexpr absl::string_view kCmacOnDataSmallTagSizeHex = "c856e183e8dee9bb9940";

using ::crypto::tink::internal::StatefulMac;
using ::crypto::tink::internal::wycheproof_testing::GetBytesFromHexValue;
using ::crypto::tink::internal::wycheproof_testing::ReadTestVectors;
using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::SecretDataAsStringView;
using ::testing::Eq;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

TEST(StatefulCmacBoringSslTest, CmacEmptyInputRegularTagSize) {
  SecretData key = util::SecretDataFromStringView(HexDecodeOrDie(kKeyHex));
  absl::StatusOr<std::unique_ptr<StatefulMac>> cmac =
      StatefulCmacBoringSsl::New(kTagSize, key);
  ASSERT_THAT(cmac, IsOk());
  absl::StatusOr<SecretData> tag = (*cmac)->FinalizeAsSecretData();
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT(SecretDataAsStringView(*tag),
              Eq(HexDecodeOrDie(kCmacOnEmptyInputRegularTagSizeHex)));
}

TEST(StatefulCmacBoringSslTest, CmacEmptyInputSmallTag) {
  SecretData key = util::SecretDataFromStringView(HexDecodeOrDie(kKeyHex));
  absl::StatusOr<std::unique_ptr<StatefulMac>> cmac =
      StatefulCmacBoringSsl::New(kSmallTagSize, key);
  ASSERT_THAT(cmac, IsOk());
  absl::StatusOr<SecretData> tag = (*cmac)->FinalizeAsSecretData();
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT(SecretDataAsStringView(*tag),
              Eq(HexDecodeOrDie(kCmacOnEmptyInputSmallTagSizeHex)));
}

TEST(StatefulCmacBoringSslTest, CmacSomeDataRegularTagSize) {
  SecretData key = util::SecretDataFromStringView(HexDecodeOrDie(kKeyHex));
  absl::StatusOr<std::unique_ptr<StatefulMac>> cmac =
      StatefulCmacBoringSsl::New(kTagSize, key);
  ASSERT_THAT(cmac, IsOk());
  EXPECT_THAT((*cmac)->Update(kData), IsOk());
  absl::StatusOr<SecretData> tag = (*cmac)->FinalizeAsSecretData();
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT(SecretDataAsStringView(*tag),
              Eq(HexDecodeOrDie(kCmacOnDataRegularTagSizeHex)));
}

TEST(StatefulCmacBoringSslTest, CmacSomeDataSmallTag) {
  SecretData key = util::SecretDataFromStringView(HexDecodeOrDie(kKeyHex));
  absl::StatusOr<std::unique_ptr<StatefulMac>> cmac =
      StatefulCmacBoringSsl::New(kSmallTagSize, key);
  ASSERT_THAT(cmac, IsOk());
  EXPECT_THAT((*cmac)->Update(kData), IsOk());
  absl::StatusOr<SecretData> tag = (*cmac)->FinalizeAsSecretData();
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT(SecretDataAsStringView(*tag),
              Eq(HexDecodeOrDie(kCmacOnDataSmallTagSizeHex)));
}

TEST(StatefulCmacBoringSslTest,
     CmacMultipleUpdatesSameAsOneForWholeInputRegularTagSize) {
  SecretData key = util::SecretDataFromStringView(HexDecodeOrDie(kKeyHex));
  absl::StatusOr<std::unique_ptr<StatefulMac>> cmac =
      StatefulCmacBoringSsl::New(kTagSize, key);
  ASSERT_THAT(cmac, IsOk());
  for (const std::string &token : {"Some ", "data ", "to ", "test."}) {
    EXPECT_THAT((*cmac)->Update(token), IsOk());
  }
  absl::StatusOr<SecretData> tag = (*cmac)->FinalizeAsSecretData();
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT(SecretDataAsStringView(*tag),
              Eq(HexDecodeOrDie(kCmacOnDataRegularTagSizeHex)));
}

TEST(StatefulCmacBoringSslTest,
     CmacMultipleUpdatesSameAsOneForWholeInputSmallTagSize) {
  SecretData key = util::SecretDataFromStringView(HexDecodeOrDie(kKeyHex));
  absl::StatusOr<std::unique_ptr<StatefulMac>> cmac =
      StatefulCmacBoringSsl::New(kSmallTagSize, key);
  ASSERT_THAT(cmac, IsOk());
  for (const std::string &token : {"Some ", "data ", "to ", "test."}) {
    EXPECT_THAT((*cmac)->Update(token), IsOk());
  }
  absl::StatusOr<SecretData> tag = (*cmac)->FinalizeAsSecretData();
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT(SecretDataAsStringView(*tag),
              Eq(HexDecodeOrDie(kCmacOnDataSmallTagSizeHex)));
}

TEST(StatefulCmacFactoryTest, FactoryGeneratesValidInstances) {
  auto factory = absl::make_unique<StatefulCmacBoringSslFactory>(
      kTagSize, util::SecretDataFromStringView(HexDecodeOrDie(kKeyHex)));
  absl::StatusOr<std::unique_ptr<StatefulMac>> cmac = factory->Create();
  ASSERT_THAT(cmac, IsOk());
  EXPECT_THAT((*cmac)->Update(kData), IsOk());
  absl::StatusOr<SecretData> tag = (*cmac)->FinalizeAsSecretData();
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT(SecretDataAsStringView(*tag),
              Eq(HexDecodeOrDie(kCmacOnDataRegularTagSizeHex)));
}

struct StatefulCmacTestVector {
  std::string key;
  std::string msg;
  std::string tag;
  std::string id;
  std::string expected_result;
};

// Reads the Wycheproof test vectors for AES-CMAC.
std::vector<StatefulCmacTestVector> GetWycheproofCmakeTestVectors() {
  absl::StatusOr<google::protobuf::Struct> parsed_input =
      ReadTestVectors("aes_cmac_test.json");
  CHECK_OK(parsed_input.status());
  std::vector<StatefulCmacTestVector> test_vectors;
  const google::protobuf::Value &test_groups =
      parsed_input->fields().at("testGroups");
  int skipped_test_groups = 0;
  for (const google::protobuf::Value &test_group :
       test_groups.list_value().values()) {
    const auto &test_group_fields = test_group.struct_value().fields();
    // Ignore test vectors of invalid key sizes; valid sizes are {16, 32} bytes.
    int key_size_bits = test_group_fields.at("keySize").number_value();
    if (key_size_bits != 128 && key_size_bits != 256) {
      skipped_test_groups++;
      continue;
    }
    for (const google::protobuf::Value &test :
         test_group_fields.at("tests").list_value().values()) {
      const auto &test_fields = test.struct_value().fields();
      test_vectors.push_back({
          /*key=*/GetBytesFromHexValue(test_fields.at("key")),
          /*msg=*/GetBytesFromHexValue(test_fields.at("msg")),
          /*tag=*/GetBytesFromHexValue(test_fields.at("tag")),
          /*id=*/absl::StrCat(test_fields.at("tcId").number_value()),
          /*expected_result=*/test_fields.at("result").string_value(),
      });
    }
  }
  CHECK_EQ(skipped_test_groups, 6);
  return test_vectors;
}

using StatefulCmacBoringSslWycheproofTest =
    TestWithParam<StatefulCmacTestVector>;

TEST_P(StatefulCmacBoringSslWycheproofTest, WycheproofTest) {
  StatefulCmacTestVector test_vector = GetParam();

  SecretData key = util::SecretDataFromStringView(HexDecodeOrDie(kKeyHex));
  absl::StatusOr<std::unique_ptr<StatefulMac>> cmac =
      StatefulCmacBoringSsl::New(
          test_vector.tag.length(),
          util::SecretDataFromStringView(test_vector.key));
  ASSERT_THAT(cmac, IsOk());
  EXPECT_THAT((*cmac)->Update(test_vector.msg), IsOk());

  absl::StatusOr<SecretData> tag = (*cmac)->FinalizeAsSecretData();
  if (test_vector.expected_result == "invalid") {
    if (!tag.ok()) {
      // Not ok is fine.
      return;
    }
    EXPECT_THAT(SecretDataAsStringView(*tag), Not(Eq(test_vector.tag)));
  } else {
    ASSERT_THAT(tag, IsOk());
    EXPECT_THAT(SecretDataAsStringView(*tag), Eq(test_vector.tag));
  }
}

INSTANTIATE_TEST_SUITE_P(StatefulCmacBoringSslWycheproofTest,
                         StatefulCmacBoringSslWycheproofTest,
                         ValuesIn(GetWycheproofCmakeTestVectors()));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
