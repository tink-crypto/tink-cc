// Copyright 2025 Google LLC
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

#include "tink/mac/internal/hmac_proto_structs.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "tink/internal/common_proto_enums.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::testing::Eq;
using ::testing::Not;

TEST(AesCtrHmacProtoStructsTest, SerializeAndParseKeyFormat) {
  HmacKeyFormatStruct key_format;
  key_format.key_size = 32;
  key_format.params.tag_size = 16;
  key_format.params.hash = HashTypeEnum::kSha256;
  key_format.version = 1;

  std::string expected_serialized_hex = "0a040803101010201801";
  absl::StatusOr<std::string> serialized =
      HmacKeyFormatStruct::GetParser().SerializeIntoString(key_format);
  ASSERT_THAT(serialized,
              IsOkAndHolds(Eq(test::HexDecodeOrDie(expected_serialized_hex))));

  absl::StatusOr<HmacKeyFormatStruct> parsed =
      HmacKeyFormatStruct::GetParser().Parse(
          test::HexDecodeOrDie(expected_serialized_hex));
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->key_size, Eq(key_format.key_size));
  EXPECT_THAT(parsed->params.tag_size, Eq(key_format.params.tag_size));
  EXPECT_THAT(parsed->params.hash, Eq(key_format.params.hash));
  EXPECT_THAT(parsed->version, Eq(key_format.version));
}

TEST(AesCtrHmacProtoStructsTest, ParseKeyFormatFailsOnInvalidInput) {
  EXPECT_THAT(HmacKeyFormatStruct::GetParser().Parse("1111"), Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
