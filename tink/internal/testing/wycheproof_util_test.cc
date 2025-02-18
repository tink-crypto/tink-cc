// Copyright 2024 Google Inc.
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

#include "tink/internal/testing/wycheproof_util.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace wycheproof_testing {

namespace {

using ::crypto::tink::subtle::EllipticCurveType;
using ::crypto::tink::subtle::HashType;
using ::crypto::tink::test::IsOk;
using ::testing::Eq;

TEST(WycheproofUtilTest, GetBytesFromHexValue) {
  google::protobuf::Value val;
  val.set_string_value("414243");
  EXPECT_THAT(GetBytesFromHexValue(val), Eq("\x41\x42\x43"));

  google::protobuf::Value val_with_odd_length;
  val_with_odd_length.set_string_value("741");
  EXPECT_THAT(GetBytesFromHexValue(val_with_odd_length), Eq("\x07\x41"));

  google::protobuf::Value val_with_leading_zero;
  val_with_leading_zero.set_string_value("0414243");
  std::string expected = "\x01\x41\x42\x43";
  expected[0] = '\0';  // the first byte is 0.
  EXPECT_THAT(GetBytesFromHexValue(val_with_leading_zero), Eq(expected));
}

TEST(WycheproofUtilTest, GetIntegerFromHexValue) {
  google::protobuf::Value val;
  val.set_string_value("414243");
  EXPECT_THAT(GetIntegerFromHexValue(val), Eq("\x41\x42\x43"));

  google::protobuf::Value val_with_odd_length;
  val_with_odd_length.set_string_value("741");
  EXPECT_THAT(GetIntegerFromHexValue(val_with_odd_length), Eq("\x07\x41"));

  google::protobuf::Value val_with_leading_zero;
  val_with_leading_zero.set_string_value("0414243");
  EXPECT_THAT(GetIntegerFromHexValue(val_with_leading_zero),
              Eq("\x41\x42\x43"));
}

TEST(WycheproofUtilTest, GetHashTypeFromValue) {
  google::protobuf::Value val;
  val.set_string_value("SHA-1");
  EXPECT_EQ(GetHashTypeFromValue(val), HashType::SHA1);
}

TEST(WycheproofUtilTest, GetEllipticCurveTypeFromValue) {
  google::protobuf::Value val;
  val.set_string_value("secp256r1");
  EXPECT_EQ(GetEllipticCurveTypeFromValue(val), EllipticCurveType::NIST_P256);
}

TEST(WycheproofUtilTest, ReadTestVectors) {
  absl::StatusOr<google::protobuf::Struct> parsed_input =
      ReadTestVectors(/*filename=*/"rsa_pss_2048_sha256_mgf1_0_test.json");
  ASSERT_THAT(parsed_input.status(), IsOk());
  const google::protobuf::Value& algorithm =
      parsed_input->fields().at("algorithm");
  const google::protobuf::Value& test_groups =
      parsed_input->fields().at("testGroups");
  const google::protobuf::Value& tests =
      test_groups.list_value().values(0).struct_value().fields().at("tests");

  EXPECT_THAT(algorithm.string_value(), Eq("RSASSA-PSS"));
  EXPECT_THAT(test_groups.list_value().values_size(), Eq(1));
  EXPECT_THAT(tests.list_value().values_size(), Eq(100));
}

}  // namespace

}  // namespace wycheproof_testing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
