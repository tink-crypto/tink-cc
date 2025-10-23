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
#include "absl/strings/str_cat.h"
#include "tink/internal/common_proto_enums.h"
#include "tink/internal/testing/field_with_number.h"
#include "tink/mac/internal/hmac_proto_structs.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;

TEST(ProtoAesCtrMessagesTest, ParseProtoAesCtrParams) {
  const std::string serialized_aes_ctr_params =
      proto_testing::FieldWithNumber(1).IsVarint(16);

  ProtoAesCtrParams params;
  ASSERT_THAT(params.ParseFromString(serialized_aes_ctr_params), IsTrue());
  EXPECT_THAT(params.iv_size(), Eq(16));
}

TEST(ProtoAesCtrMessagesTest, ParseProtoAesCtrParamsInvalid) {
  ProtoAesCtrParams params;
  EXPECT_THAT(params.ParseFromString("invalid"), IsFalse());
}

TEST(ProtoAesCtrMessagesTest, SerializeProtoAesCtrParams) {
  ProtoAesCtrParams params;
  params.set_iv_size(16);

  auto serialized_aes_ctr_params = params.SerializeAsSecretData();
  EXPECT_THAT(util::SecretDataAsStringView(serialized_aes_ctr_params),
              Eq(proto_testing::FieldWithNumber(1).IsVarint(16)));
}

TEST(ProtoAesCtrMessagesTest, ParseProtoAesCtrKeyFormat) {
  const std::string serialized_aes_ctr_key_format =
      absl::StrCat(proto_testing::FieldWithNumber(1).IsSubMessage(
                       {proto_testing::FieldWithNumber(1).IsVarint(12)}),
                   proto_testing::FieldWithNumber(2).IsVarint(32));

  ProtoAesCtrKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(serialized_aes_ctr_key_format),
              IsTrue());
  EXPECT_THAT(key_format.params().iv_size(), Eq(12));
  EXPECT_THAT(key_format.key_size(), Eq(32));
}

TEST(ProtoAesCtrMessagesTest, ParseProtoAesCtrKeyFormatInvalid) {
  ProtoAesCtrKeyFormat key_format;
  EXPECT_THAT(key_format.ParseFromString("invalid"), IsFalse());
}

TEST(ProtoAesCtrMessagesTest, SerializeProtoAesCtrKeyFormat) {
  ProtoAesCtrKeyFormat key_format;
  key_format.mutable_params()->set_iv_size(12);
  key_format.set_key_size(32);

  std::string expected_serialized_key_format =
      absl::StrCat(proto_testing::FieldWithNumber(1).IsSubMessage(
                       {proto_testing::FieldWithNumber(1).IsVarint(12)}),
                   proto_testing::FieldWithNumber(2).IsVarint(32));

  auto serialized_aes_ctr_key_format = key_format.SerializeAsSecretData();
  EXPECT_THAT(util::SecretDataAsStringView(serialized_aes_ctr_key_format),
              Eq(expected_serialized_key_format));
}

std::string GetSerializedAesCtrHmacAeadKeyFormat() {
  ProtoAesCtrKeyFormat aes_ctr_key_format;
  aes_ctr_key_format.mutable_params()->set_iv_size(12);
  aes_ctr_key_format.set_key_size(16);

  ProtoHmacKeyFormat hmac_key_format;
  hmac_key_format.mutable_params()->set_hash(HashTypeEnum::kSha256);
  hmac_key_format.mutable_params()->set_tag_size(16);
  hmac_key_format.set_key_size(32);
  hmac_key_format.set_version(1);

  return absl::StrCat(proto_testing::FieldWithNumber(1).IsSubMessage(
                          {std::string(util::SecretDataAsStringView(
                              aes_ctr_key_format.SerializeAsSecretData()))}),
                      proto_testing::FieldWithNumber(2).IsSubMessage(
                          {std::string(util::SecretDataAsStringView(
                              hmac_key_format.SerializeAsSecretData()))}));
}

TEST(ProtoAesCtrMessagesTest, ParseProtoAesCtrHmacAeadKeyFormat) {
  ProtoAesCtrHmacAeadKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(GetSerializedAesCtrHmacAeadKeyFormat()),
      IsTrue());
  EXPECT_THAT(key_format.aes_ctr_key_format().params().iv_size(), Eq(12));
  EXPECT_THAT(key_format.aes_ctr_key_format().key_size(), Eq(16));
  EXPECT_THAT(key_format.hmac_key_format().params().hash(),
              Eq(HashTypeEnum::kSha256));
  EXPECT_THAT(key_format.hmac_key_format().params().tag_size(), Eq(16));
  EXPECT_THAT(key_format.hmac_key_format().key_size(), Eq(32));
  EXPECT_THAT(key_format.hmac_key_format().version(), Eq(1));
}

TEST(ProtoAesCtrMessagesTest, ParseProtoAesCtrHmacAeadKeyFormatInvalid) {
  ProtoAesCtrHmacAeadKeyFormat key_format;
  EXPECT_THAT(key_format.ParseFromString("invalid"), IsFalse());
}

TEST(ProtoAesCtrMessagesTest, SerializeProtoAesCtrHmacAeadKeyFormat) {
  ProtoAesCtrHmacAeadKeyFormat key_format;
  key_format.mutable_aes_ctr_key_format()->mutable_params()->set_iv_size(12);
  key_format.mutable_aes_ctr_key_format()->set_key_size(16);
  key_format.mutable_hmac_key_format()->mutable_params()->set_hash(
      HashTypeEnum::kSha256);
  key_format.mutable_hmac_key_format()->mutable_params()->set_tag_size(16);
  key_format.mutable_hmac_key_format()->set_key_size(32);
  key_format.mutable_hmac_key_format()->set_version(1);

  const std::string expected_serialized_key_format =
      GetSerializedAesCtrHmacAeadKeyFormat();

  auto serialized_key_format = key_format.SerializeAsSecretData();
  EXPECT_THAT(util::SecretDataAsStringView(serialized_key_format),
              Eq(expected_serialized_key_format));
}

std::string GetSerializedAesCtrKey() {
  ProtoAesCtrParams params;
  params.set_iv_size(16);
  return absl::StrCat(
      proto_testing::FieldWithNumber(1).IsVarint(1),  // version
      proto_testing::FieldWithNumber(2).IsSubMessage({std::string(
          util::SecretDataAsStringView(params.SerializeAsSecretData()))}),
      proto_testing::FieldWithNumber(3).IsString(
          "0123456789012345"));  // key_value
}

TEST(ProtoAesCtrMessagesTest, ParseProtoAesCtrKey) {
  const std::string serialized_aes_ctr_key = GetSerializedAesCtrKey();
  ProtoAesCtrKey key;
  ASSERT_THAT(key.ParseFromString(serialized_aes_ctr_key), IsTrue());
  EXPECT_THAT(key.version(), Eq(1));
  EXPECT_THAT(key.params().iv_size(), Eq(16));
  EXPECT_THAT(util::SecretDataAsStringView(key.key_value()),
              Eq("0123456789012345"));
}

TEST(ProtoAesCtrMessagesTest, ParseProtoAesCtrKeyInvalid) {
  ProtoAesCtrKey key;
  EXPECT_THAT(key.ParseFromString("invalid"), IsFalse());
}

TEST(ProtoAesCtrMessagesTest, SerializeProtoAesCtrKey) {
  ProtoAesCtrKey key;
  key.set_version(1);
  key.mutable_params()->set_iv_size(16);
  key.set_key_value("0123456789012345");

  auto serialized_aes_ctr_key = key.SerializeAsSecretData();
  const std::string expected_serialized_aes_ctr_key = GetSerializedAesCtrKey();
  EXPECT_THAT(util::SecretDataAsStringView(serialized_aes_ctr_key),
              Eq(expected_serialized_aes_ctr_key));
}

std::string GetSerializedHmacKey() {
  ProtoHmacParams params;
  params.set_hash(HashTypeEnum::kSha256);
  params.set_tag_size(16);
  return absl::StrCat(
      proto_testing::FieldWithNumber(1).IsVarint(1),  // version
      proto_testing::FieldWithNumber(2).IsSubMessage({std::string(
          util::SecretDataAsStringView(params.SerializeAsSecretData()))}),
      proto_testing::FieldWithNumber(3).IsString(
          "01234567890123456789012345678901"));  // key_value
}

std::string GetSerializedAesCtrHmacAeadKey() {
  return absl::StrCat(proto_testing::FieldWithNumber(1).IsVarint(1),  // version
                      proto_testing::FieldWithNumber(2).IsString(
                          GetSerializedAesCtrKey()),  // aes_ctr_key
                      proto_testing::FieldWithNumber(3).IsString(
                          GetSerializedHmacKey()));  // hmac_key
}

TEST(ProtoAesCtrMessagesTest, ParseProtoAesCtrHmacAeadKey) {
  const std::string serialized_key = GetSerializedAesCtrHmacAeadKey();
  ProtoAesCtrHmacAeadKey key;
  ASSERT_THAT(key.ParseFromString(serialized_key), IsTrue());
  EXPECT_THAT(key.version(), Eq(1));
  EXPECT_THAT(key.aes_ctr_key().version(), Eq(1));
  EXPECT_THAT(key.aes_ctr_key().params().iv_size(), Eq(16));
  EXPECT_THAT(util::SecretDataAsStringView(key.aes_ctr_key().key_value()),
              Eq("0123456789012345"));
  EXPECT_THAT(key.hmac_key().version(), Eq(1));
  EXPECT_THAT(key.hmac_key().params().hash(), Eq(HashTypeEnum::kSha256));
  EXPECT_THAT(key.hmac_key().params().tag_size(), Eq(16));
  EXPECT_THAT(util::SecretDataAsStringView(key.hmac_key().key_value()),
              Eq("01234567890123456789012345678901"));
}

TEST(ProtoAesCtrMessagesTest, ParseProtoAesCtrHmacAeadKeyInvalid) {
  ProtoAesCtrHmacAeadKey key;
  EXPECT_THAT(key.ParseFromString("invalid"), IsFalse());
}

TEST(ProtoAesCtrMessagesTest, SerializeProtoAesCtrHmacAeadKey) {
  ProtoAesCtrHmacAeadKey key;
  key.set_version(1);
  key.mutable_aes_ctr_key()->set_version(1);
  key.mutable_aes_ctr_key()->mutable_params()->set_iv_size(16);
  key.mutable_aes_ctr_key()->set_key_value("0123456789012345");
  key.mutable_hmac_key()->set_version(1);
  key.mutable_hmac_key()->mutable_params()->set_hash(HashTypeEnum::kSha256);
  key.mutable_hmac_key()->mutable_params()->set_tag_size(16);
  key.mutable_hmac_key()->set_key_value("01234567890123456789012345678901");

  auto serialized_key = key.SerializeAsSecretData();
  const std::string expected_serialized_key = GetSerializedAesCtrHmacAeadKey();
  EXPECT_THAT(util::SecretDataAsStringView(serialized_key),
              Eq(expected_serialized_key));
}

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

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
