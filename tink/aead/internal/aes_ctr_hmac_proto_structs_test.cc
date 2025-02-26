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

#include "tink/aead/internal/aes_ctr_hmac_proto_structs.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "tink/internal/common_proto_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::util::SecretDataAsStringView;
using ::testing::Eq;
using ::testing::Not;

TEST(AesCtrHmacProtoStructsTest, SerializeAndParseKeyFormat) {
  AesCtrHmacAeadKeyFormatStruct key_format;
  key_format.aes_ctr_key_format.key_size = 32;
  key_format.aes_ctr_key_format.params.iv_size = 20;
  key_format.hmac_key_format.key_size = 32;
  key_format.hmac_key_format.params.tag_size = 16;
  key_format.hmac_key_format.params.hash = HashTypeEnum::kSha256;
  key_format.hmac_key_format.version = 1;

  std::string expected_serialized_hex =
      "0a060a0208141020120a0a040803101010201801";
  absl::StatusOr<std::string> serialized =
      AesCtrHmacAeadKeyFormatStruct::GetParser().SerializeIntoString(
          key_format);
  ASSERT_THAT(serialized,
              IsOkAndHolds(Eq(test::HexDecodeOrDie(expected_serialized_hex))));

  absl::StatusOr<AesCtrHmacAeadKeyFormatStruct> parsed =
      AesCtrHmacAeadKeyFormatStruct::GetParser().Parse(
          test::HexDecodeOrDie(expected_serialized_hex));
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->aes_ctr_key_format.key_size,
              Eq(key_format.aes_ctr_key_format.key_size));
  EXPECT_THAT(parsed->aes_ctr_key_format.params.iv_size,
              Eq(key_format.aes_ctr_key_format.params.iv_size));
  EXPECT_THAT(parsed->hmac_key_format.key_size,
              Eq(key_format.hmac_key_format.key_size));
  EXPECT_THAT(parsed->hmac_key_format.params.tag_size,
              Eq(key_format.hmac_key_format.params.tag_size));
  EXPECT_THAT(parsed->hmac_key_format.params.hash,
              Eq(key_format.hmac_key_format.params.hash));
  EXPECT_THAT(parsed->hmac_key_format.version,
              Eq(key_format.hmac_key_format.version));
}

TEST(AesCtrHmacProtoStructsTest, ParseKeyFormatFailsOnInvalidInput) {
  EXPECT_THAT(AesCtrHmacAeadKeyFormatStruct::GetParser().Parse("1111"),
              Not(IsOk()));
}

TEST(AesCtrHmacProtoStructsTest, SerializeAndParseKey) {
  AesCtrHmacAeadKeyStruct key_struct;
  key_struct.version = 1;
  key_struct.aes_ctr_key.version = 1;
  key_struct.aes_ctr_key.params.iv_size = 16;
  key_struct.aes_ctr_key.key_value =
      util::SecretDataFromStringView("0123456789abcdef");
  key_struct.hmac_key.version = 1;
  key_struct.hmac_key.params.tag_size = 16;
  key_struct.hmac_key.params.hash = HashTypeEnum::kSha256;
  key_struct.hmac_key.key_value =
      util::SecretDataFromStringView("abcdef0123456789");

  std::string expected_serialized_hex =
      "080112180801120208101a10303132333435363738396162636465661a1a080112040803"
      "10101a1061626364656630313233343536373839";
  absl::StatusOr<std::string> serialized =
      AesCtrHmacAeadKeyStruct::GetParser().SerializeIntoString(key_struct);
  ASSERT_THAT(serialized,
              IsOkAndHolds(Eq(test::HexDecodeOrDie(expected_serialized_hex))));

  absl::StatusOr<AesCtrHmacAeadKeyStruct> parsed =
      AesCtrHmacAeadKeyStruct::GetParser().Parse(
          test::HexDecodeOrDie(expected_serialized_hex));
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->version, Eq(key_struct.version));
  EXPECT_THAT(parsed->aes_ctr_key.version, Eq(key_struct.aes_ctr_key.version));
  EXPECT_THAT(parsed->aes_ctr_key.params.iv_size,
              Eq(key_struct.aes_ctr_key.params.iv_size));
  EXPECT_THAT(SecretDataAsStringView(parsed->aes_ctr_key.key_value),
              Eq(SecretDataAsStringView(key_struct.aes_ctr_key.key_value)));
  EXPECT_THAT(parsed->hmac_key.version, Eq(key_struct.hmac_key.version));
  EXPECT_THAT(parsed->hmac_key.params.tag_size,
              Eq(key_struct.hmac_key.params.tag_size));
  EXPECT_THAT(parsed->hmac_key.params.hash,
              Eq(key_struct.hmac_key.params.hash));
  EXPECT_THAT(SecretDataAsStringView(parsed->hmac_key.key_value),
              Eq(SecretDataAsStringView(key_struct.hmac_key.key_value)));
}

TEST(AesCtrHmacProtoStructsTest, ParseKeyFailsOnInvalidInput) {
  EXPECT_THAT(AesCtrHmacAeadKeyStruct::GetParser().Parse("1111111111"),
              Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
