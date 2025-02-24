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

#include "tink/aead/internal/aes_gcm_proto_structs.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"
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
using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Field;
using ::testing::Not;

TEST(AesGcmProtoStructsTest, SerializeAndParseKeyFormat) {
  AesGcmKeyFormatStruct key_format;
  key_format.key_size = 32;
  key_format.version = 1;

  std::string expected_serialized_hex = "10201801";
  absl::StatusOr<std::string> serialized =
      AesGcmKeyFormatStruct::GetParser().SerializeIntoString(key_format);
  ASSERT_THAT(serialized,
              IsOkAndHolds(Eq(test::HexDecodeOrDie(expected_serialized_hex))));

  absl::StatusOr<AesGcmKeyFormatStruct> parsed =
      AesGcmKeyFormatStruct::GetParser().Parse(
          test::HexDecodeOrDie(expected_serialized_hex));
  EXPECT_THAT(
      parsed,
      IsOkAndHolds(AllOf(
          Field(&AesGcmKeyFormatStruct::key_size, Eq(key_format.key_size)),
          Field(&AesGcmKeyFormatStruct::version, Eq(key_format.version)))));
}

TEST(AesGcmProtoStructsTest, ParseKeyFormatFailsOnInvalidInput) {
  EXPECT_THAT(AesGcmKeyFormatStruct::GetParser().Parse("1111"), Not(IsOk()));
}

TEST(AesGcmProtoStructsTest, SerializeAndParseKey) {
  AesGcmKeyStruct key_struct;
  key_struct.version = 1;
  key_struct.key_value = util::SecretDataFromStringView("0123456789abcdef");

  std::string expected_serialized_hex =
      "08011a1030313233343536373839616263646566";
  absl::StatusOr<std::string> serialized =
      AesGcmKeyStruct::GetParser().SerializeIntoString(key_struct);
  ASSERT_THAT(serialized,
              IsOkAndHolds(Eq(test::HexDecodeOrDie(expected_serialized_hex))));

  absl::StatusOr<AesGcmKeyStruct> parsed = AesGcmKeyStruct::GetParser().Parse(
      test::HexDecodeOrDie(expected_serialized_hex));
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->version, Eq(key_struct.version));
  EXPECT_THAT(SecretDataAsStringView(parsed->key_value),
              Eq(SecretDataAsStringView(key_struct.key_value)));
}

TEST(AesGcmProtoStructsTest, ParseKeyFailsOnInvalidInput) {
  EXPECT_THAT(AesGcmKeyStruct::GetParser().Parse("1111111111"), Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
