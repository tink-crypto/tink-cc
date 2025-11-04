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
#include "absl/strings/str_cat.h"
#include "tink/internal/common_proto_enums.h"
#include "tink/internal/testing/field_with_number.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;

TEST(ProtoHmacMessagesTest, ParseHmacParamsTP) {
  const std::string serialized_hmac_params =
      absl::StrCat(proto_testing::FieldWithNumber(1).IsVarint(3),
                   proto_testing::FieldWithNumber(2).IsVarint(16));

  HmacParamsTP params;
  ASSERT_THAT(params.ParseFromString(serialized_hmac_params), IsTrue());
  EXPECT_THAT(params.hash(), Eq(HashTypeEnum::kSha256));
  EXPECT_THAT(params.tag_size(), Eq(16));
}

TEST(ProtoHmacMessagesTest, ParseHmacParamsInvalidTP) {
  HmacParamsTP params;
  EXPECT_THAT(params.ParseFromString("invalid"), IsFalse());
}

TEST(ProtoHmacMessagesTest, SerializeHmacParamsTP) {
  HmacParamsTP params;
  params.set_hash(HashTypeEnum::kSha256);
  params.set_tag_size(16);

  auto serialized_hmac_params = params.SerializeAsSecretData();
  EXPECT_THAT(util::SecretDataAsStringView(serialized_hmac_params),
              Eq(absl::StrCat(proto_testing::FieldWithNumber(1).IsVarint(3),
                              proto_testing::FieldWithNumber(2).IsVarint(16))));
}

TEST(ProtoHmacMessagesTest, ParseHmacKeyFormatTP) {
  const std::string serialized_hmac_format =
      absl::StrCat(proto_testing::FieldWithNumber(1).IsSubMessage(
                       {proto_testing::FieldWithNumber(1).IsVarint(3),
                        proto_testing::FieldWithNumber(2).IsVarint(16)}),
                   proto_testing::FieldWithNumber(2).IsVarint(32),  // key_size
                   proto_testing::FieldWithNumber(3).IsVarint(1)    // version
      );

  HmacKeyFormatTP format;
  ASSERT_THAT(format.ParseFromString(serialized_hmac_format), IsTrue());
  EXPECT_THAT(format.params().hash(), Eq(HashTypeEnum::kSha256));
  EXPECT_THAT(format.params().tag_size(), Eq(16));
  EXPECT_THAT(format.key_size(), Eq(32));
  EXPECT_THAT(format.version(), Eq(1));
}

TEST(ProtoHmacMessagesTest, ParseHmacKeyFormatInvalidTP) {
  HmacKeyFormatTP format;
  EXPECT_THAT(format.ParseFromString("invalid"), IsFalse());
}

TEST(ProtoHmacMessagesTest, SerializeHmacKeyFormatTP) {
  HmacKeyFormatTP format;
  format.mutable_params()->set_hash(HashTypeEnum::kSha256);
  format.mutable_params()->set_tag_size(16);
  format.set_key_size(32);
  format.set_version(1);

  auto serialized_hmac_format = format.SerializeAsSecretData();
  const std::string expected_serialized_hmac_format =
      absl::StrCat(proto_testing::FieldWithNumber(1).IsSubMessage(
                       {proto_testing::FieldWithNumber(1).IsVarint(3),
                        proto_testing::FieldWithNumber(2).IsVarint(16)}),
                   proto_testing::FieldWithNumber(2).IsVarint(32),  // key_size
                   proto_testing::FieldWithNumber(3).IsVarint(1)    // version
      );
  EXPECT_THAT(util::SecretDataAsStringView(serialized_hmac_format),
              Eq(expected_serialized_hmac_format));
}

TEST(ProtoHmacMessagesTest, ParseHmacKeyTP) {
  const std::string serialized_hmac_key =
      absl::StrCat(proto_testing::FieldWithNumber(2).IsSubMessage(
                       {proto_testing::FieldWithNumber(1).IsVarint(3),
                        proto_testing::FieldWithNumber(2).IsVarint(16)}),
                   proto_testing::FieldWithNumber(3).IsString(
                       "01234567890123456789012345678901"),       // key_value
                   proto_testing::FieldWithNumber(1).IsVarint(1)  // version
      );

  HmacKeyTP key;
  ASSERT_THAT(key.ParseFromString(serialized_hmac_key), IsTrue());
  EXPECT_THAT(key.params().hash(), Eq(HashTypeEnum::kSha256));
  EXPECT_THAT(key.params().tag_size(), Eq(16));
  EXPECT_THAT(util::SecretDataAsStringView(key.key_value()),
              Eq("01234567890123456789012345678901"));
  EXPECT_THAT(key.version(), Eq(1));
}

TEST(ProtoHmacMessagesTest, ParseHmacKeyInvalidTP) {
  HmacKeyTP key;
  EXPECT_THAT(key.ParseFromString("invalid"), IsFalse());
}

TEST(ProtoHmacMessagesTest, SerializeHmacKeyTP) {
  HmacKeyTP key;
  key.mutable_params()->set_hash(HashTypeEnum::kSha256);
  key.mutable_params()->set_tag_size(16);
  key.set_key_value("01234567890123456789012345678901");
  key.set_version(1);

  auto serialized_hmac_key = key.SerializeAsSecretData();
  const std::string expected_serialized_hmac_key =
      absl::StrCat(proto_testing::FieldWithNumber(1).IsVarint(1),  // version
                   proto_testing::FieldWithNumber(2).IsSubMessage(
                       {proto_testing::FieldWithNumber(1).IsVarint(3),
                        proto_testing::FieldWithNumber(2).IsVarint(16)}),
                   proto_testing::FieldWithNumber(3).IsString(
                       "01234567890123456789012345678901")  // key_value
      );
  EXPECT_THAT(util::SecretDataAsStringView(serialized_hmac_key),
              Eq(expected_serialized_hmac_key));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
