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

#include "tink/json/json_keyset_reader.h"

#include <ios>
#include <iostream>
#include <istream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/substitute.h"
#include "tink/keyset_reader.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_eax.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::AddRawKey;
using ::crypto::tink::test::AddTinkKey;
using ::crypto::tink::test::IsOk;

using AesEaxKeyProto = ::google::crypto::tink::AesEaxKey;
using AesGcmKeyProto = ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::EncryptedKeyset;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::Not;

namespace {

class JsonKeysetReaderTest : public ::testing::Test {
 protected:
  void SetUp() override {
    gcm_key_.set_key_value("some gcm key value");
    gcm_key_.set_version(0);

    eax_key_.set_key_value("some eax key value");
    eax_key_.set_version(0);
    eax_key_.mutable_params()->set_iv_size(16);

    AddTinkKey("type.googleapis.com/google.crypto.tink.AesGcmKey", 42, gcm_key_,
               KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset_);
    AddRawKey("type.googleapis.com/google.crypto.tink.AesEaxKey", 711, eax_key_,
              KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset_);
    keyset_.set_primary_key_id(42);
    good_json_keyset_ = absl::Substitute(
        R"(
      {
         "primaryKeyId":42,
         "key":[
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "$0"
               },
               "outputPrefixType":"TINK",
               "keyId":42,
               "status":"ENABLED"
            },
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesEaxKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value":"$1"
               },
               "outputPrefixType":"RAW",
               "keyId":711,
               "status":"ENABLED"
            }
         ]
      })",
        absl::Base64Escape(gcm_key_.SerializeAsString()),
        absl::Base64Escape(eax_key_.SerializeAsString()));

    bad_json_keyset_ = "some weird string";

    std::string enc_keyset = "some ciphertext with keyset";
    encrypted_keyset_.set_encrypted_keyset(enc_keyset);
    std::string enc_keyset_base64;
    absl::Base64Escape(enc_keyset, &enc_keyset_base64);
    auto keyset_info = encrypted_keyset_.mutable_keyset_info();
    keyset_info->set_primary_key_id(42);
    auto key_info = keyset_info->add_key_info();
    key_info->set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
    key_info->set_key_id(42);
    key_info->set_output_prefix_type(OutputPrefixType::TINK);
    key_info->set_status(KeyStatusType::ENABLED);
    good_json_encrypted_keyset_ =
        "{"
        "\"encryptedKeyset\": \"" +
        enc_keyset_base64 +
        "\", "
        "\"keysetInfo\": {"
        "  \"primaryKeyId\": 42,"
        "  \"keyInfo\": ["
        "    {"
        "      \"typeUrl\":"
        "        \"type.googleapis.com/google.crypto.tink.AesGcmKey\","
        "      \"outputPrefixType\": \"TINK\","
        "      \"keyId\": 42,"
        "      \"status\": \"ENABLED\""
        "    }"
        "  ]"
        "}}";
  }

  EncryptedKeyset encrypted_keyset_;
  Keyset keyset_;
  std::string bad_json_keyset_;
  std::string good_json_keyset_;
  std::string good_json_encrypted_keyset_;

  // Some prepopulated keys.
  AesGcmKeyProto gcm_key_;
  AesEaxKeyProto eax_key_;
};

TEST_F(JsonKeysetReaderTest, testReaderCreation) {
  {  // Input stream is null.
    std::unique_ptr<std::istream> null_stream(nullptr);
    auto reader_result = JsonKeysetReader::New(std::move(null_stream));
    EXPECT_FALSE(reader_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
              reader_result.status().code());
  }

  {  // Good serialized keyset.
    auto reader_result = JsonKeysetReader::New(good_json_keyset_);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  }

  {  // Stream with good keyset.
    std::unique_ptr<std::istream> good_keyset_stream(new std::stringstream(
        std::string(good_json_keyset_), std::ios_base::in));
    auto reader_result = JsonKeysetReader::New(std::move(good_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  }

  {  // Bad serialized keyset.
    auto reader_result = JsonKeysetReader::New(bad_json_keyset_);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  }

  {  // Stream with bad keyset.
    std::unique_ptr<std::istream> bad_keyset_stream(new std::stringstream(
        std::string(bad_json_keyset_), std::ios_base::in));
    auto reader_result = JsonKeysetReader::New(std::move(bad_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  }
}

TEST_F(JsonKeysetReaderTest, testReadFromString) {
  {  // Good string.
    auto reader_result = JsonKeysetReader::New(good_json_keyset_);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.value());
    auto read_result = reader->Read();
    EXPECT_TRUE(read_result.ok()) << read_result.status();
    auto keyset = std::move(read_result.value());
    EXPECT_EQ(keyset_.SerializeAsString(), keyset->SerializeAsString());
  }

  {  // Bad string.
    auto reader_result = JsonKeysetReader::New(bad_json_keyset_);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.value());
    auto read_result = reader->Read();
    EXPECT_FALSE(read_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, read_result.status().code());
  }

  {  // A valid JSON value, but not a JSON object.
    auto reader_result = JsonKeysetReader::New("124");
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.value());
    auto read_result = reader->Read();
    EXPECT_FALSE(read_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, read_result.status().code());
  }
}

TEST_F(JsonKeysetReaderTest, testReadFromStream) {
  {  // Good stream.
    std::unique_ptr<std::istream> good_keyset_stream(new std::stringstream(
        std::string(good_json_keyset_), std::ios_base::in));
    auto reader_result = JsonKeysetReader::New(std::move(good_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.value());
    auto read_result = reader->Read();
    EXPECT_TRUE(read_result.ok()) << read_result.status();
    auto keyset = std::move(read_result.value());
    EXPECT_EQ(keyset_.SerializeAsString(), keyset->SerializeAsString());
  }

  {  // Bad stream.
    std::unique_ptr<std::istream> bad_keyset_stream(new std::stringstream(
        std::string(bad_json_keyset_), std::ios_base::in));
    auto reader_result = JsonKeysetReader::New(std::move(bad_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.value());
    auto read_result = reader->Read();
    EXPECT_FALSE(read_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, read_result.status().code());
  }
}

TEST_F(JsonKeysetReaderTest, testReadEncryptedFromString) {
  {  // Good string.
    auto reader_result = JsonKeysetReader::New(good_json_encrypted_keyset_);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.value());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_TRUE(read_encrypted_result.ok()) << read_encrypted_result.status();
    auto encrypted_keyset = std::move(read_encrypted_result.value());
    EXPECT_EQ(encrypted_keyset_.SerializeAsString(),
              encrypted_keyset->SerializeAsString());
  }

  {  // Bad string.
    auto reader_result = JsonKeysetReader::New(bad_json_keyset_);
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.value());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_FALSE(read_encrypted_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
              read_encrypted_result.status().code());
  }
}

TEST_F(JsonKeysetReaderTest, testReadEncryptedFromStream) {
  {  // Good stream.
    std::unique_ptr<std::istream> good_encrypted_keyset_stream(
        new std::stringstream(std::string(good_json_encrypted_keyset_),
                              std::ios_base::in));
    auto reader_result =
        JsonKeysetReader::New(std::move(good_encrypted_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.value());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_TRUE(read_encrypted_result.ok()) << read_encrypted_result.status();
    auto encrypted_keyset = std::move(read_encrypted_result.value());
    EXPECT_EQ(encrypted_keyset_.SerializeAsString(),
              encrypted_keyset->SerializeAsString());
  }

  {  // Bad string.
    std::unique_ptr<std::istream> bad_keyset_stream(new std::stringstream(
        std::string(bad_json_keyset_), std::ios_base::in));
    auto reader_result = JsonKeysetReader::New(std::move(bad_keyset_stream));
    EXPECT_TRUE(reader_result.ok()) << reader_result.status();
    auto reader = std::move(reader_result.value());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_FALSE(read_encrypted_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
              read_encrypted_result.status().code());
  }
}

TEST_F(JsonKeysetReaderTest, ReadLargeKeyId) {
  std::string json_serialization =
      absl::Substitute(R"(
      {
         "primaryKeyId": 4294967275,
         "key":[
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "$0"
               },
               "outputPrefixType":"TINK",
               "keyId": 4294967275,
               "status":"ENABLED"
            },
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesEaxKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value":"$1"
               },
               "outputPrefixType":"RAW",
               "keyId":711,
               "status":"ENABLED"
            }
         ]
      })",
                       absl::Base64Escape(gcm_key_.SerializeAsString()),
                       absl::Base64Escape(eax_key_.SerializeAsString()));
  auto reader_result = JsonKeysetReader::New(json_serialization);
  ASSERT_THAT(reader_result, IsOk());
  auto reader = std::move(reader_result.value());
  auto read_result = reader->Read();
  ASSERT_THAT(read_result, IsOk());
  auto keyset = std::move(read_result.value());
  EXPECT_THAT(keyset->primary_key_id(), Eq(4294967275));
}

TEST_F(JsonKeysetReaderTest, RejectsNegativeKeyIds) {
  std::string json_serialization =
      absl::Substitute(R"(
      {
         "primaryKeyId": 711,
         "key":[
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "$0"
               },
               "outputPrefixType":"TINK",
               "keyId": -21,
               "status":"ENABLED"
            },
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesEaxKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value":"$1"
               },
               "outputPrefixType":"RAW",
               "keyId":711,
               "status":"ENABLED"
            }
         ]
      })",
                       absl::Base64Escape(gcm_key_.SerializeAsString()),
                       absl::Base64Escape(eax_key_.SerializeAsString()));
  auto reader_result = JsonKeysetReader::New(json_serialization);
  ASSERT_THAT(reader_result, IsOk());
  auto reader = std::move(reader_result.value());
  auto read_result = reader->Read();
  EXPECT_THAT(read_result, Not(IsOk()));
}

TEST_F(JsonKeysetReaderTest, RejectsKeyIdLargerThanUint32) {
  // 4294967296 = 2^32, which is too large for uint32.
  std::string json_serialization =
      absl::Substitute(R"(
      {
         "primaryKeyId": 711,
         "key":[
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "$0"
               },
               "outputPrefixType":"TINK",
               "keyId": 4294967296,
               "status":"ENABLED"
            },
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesEaxKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value":"$1"
               },
               "outputPrefixType":"RAW",
               "keyId":711,
               "status":"ENABLED"
            }
         ]
      })",
                       absl::Base64Escape(gcm_key_.SerializeAsString()),
                       absl::Base64Escape(eax_key_.SerializeAsString()));
  auto reader_result = JsonKeysetReader::New(json_serialization);
  ASSERT_THAT(reader_result, IsOk());
  auto reader = std::move(reader_result.value());
  auto read_result = reader->Read();
  EXPECT_THAT(read_result, Not(IsOk()));
}


TEST_F(JsonKeysetReaderTest, parseRecursiveJsonStringFails) {
  std::string recursive_json;
  for (int i = 0; i < 1000000; i++) {
    recursive_json.append("{\"a\":");
  }
  recursive_json.append("1");
  for (int i = 0; i < 1000000; i++) {
    recursive_json.append("}");
  }
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      JsonKeysetReader::New(recursive_json);
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<Keyset>> keyset = (*reader)->Read();
  EXPECT_THAT(keyset, Not(IsOk()));
}

TEST_F(JsonKeysetReaderTest, MissingPrimaryKeyHasValueZero) {
  std::string keyset_without_primary = R"(
      {
         "key":[
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
               },
               "outputPrefixType":"TINK",
               "keyId": 42,
               "status":"ENABLED"
            }
         ]
      })";
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      JsonKeysetReader::New(keyset_without_primary);
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<google::crypto::tink::Keyset>> keyset =
      (*reader)->Read();
  EXPECT_THAT(keyset, IsOk());
  EXPECT_THAT((*keyset)->primary_key_id(), Eq(0));
}

TEST_F(JsonKeysetReaderTest, ReadKeysetsWithInvalidStatus) {
  std::string keyset_with_invalid_status = R"(
      {
         "primaryKeyId":42,
         "key":[
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
               },
               "outputPrefixType":"TINK",
               "keyId": 42,
               "status":"INVALID"
            }
         ]
      })";
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      JsonKeysetReader::New(keyset_with_invalid_status);
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<google::crypto::tink::Keyset>> keyset =
      (*reader)->Read();
  EXPECT_THAT(keyset, Not(IsOk()));
}

TEST_F(JsonKeysetReaderTest, ReadKeysetsWithTailingCommaInArray) {
  std::string keyset_with_invalid_status = R"(
      {
         "primaryKeyId":42,
         "key":[
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
               },
               "outputPrefixType":"TINK",
               "keyId": 42,
               "status":"ENABLED"
            },
         ]
      })";
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      JsonKeysetReader::New(keyset_with_invalid_status);
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<google::crypto::tink::Keyset>> keyset =
      (*reader)->Read();
  EXPECT_THAT(keyset, IsOk());
}

TEST_F(JsonKeysetReaderTest, ReadKeysetsWithTailingCommaInObject) {
  std::string keyset_with_invalid_status = R"(
      {
         "primaryKeyId":42,
         "key":[
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
               },
               "outputPrefixType":"TINK",
               "keyId": 42,
               "status":"ENABLED",
            }
         ]
      })";
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      JsonKeysetReader::New(keyset_with_invalid_status);
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<google::crypto::tink::Keyset>> keyset =
      (*reader)->Read();
  EXPECT_THAT(keyset, IsOk());
}

TEST_F(JsonKeysetReaderTest, ReadKeysetsWithInvalidOutputPrefixType) {
  std::string keyset_with_invalid_prefix_type = R"(
      {
         "primaryKeyId":42,
         "key":[
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
               },
               "outputPrefixType":"INVALID",
               "keyId": 42,
               "status":"ENABLED"
            }
         ]
      })";
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      JsonKeysetReader::New(keyset_with_invalid_prefix_type);
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<google::crypto::tink::Keyset>> keyset =
      (*reader)->Read();
  EXPECT_THAT(keyset, Not(IsOk()));
}


TEST_F(JsonKeysetReaderTest, ReadKeysetsWithInvalidKeyMaterialType) {
  std::string keyset_with_invalid_prefix_type = R"(
      {
         "primaryKeyId":42,
         "key":[
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"INVALID",
                  "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
               },
               "outputPrefixType":"TINK",
               "keyId": 42,
               "status":"ENABLED"
            }
         ]
      })";
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      JsonKeysetReader::New(keyset_with_invalid_prefix_type);
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<google::crypto::tink::Keyset>> keyset =
      (*reader)->Read();
  EXPECT_THAT(keyset, Not(IsOk()));
}

TEST_F(JsonKeysetReaderTest, ReadKeysetsWithKeyNotArray) {
  const std::string keyset_with_key_not_array = R"(
      {
         "primaryKeyId":42,
         "key":
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
               },
               "outputPrefixType":"TINK",
               "keyId": 42,
               "status":"ENABLED"
            }
      })";
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      JsonKeysetReader::New(keyset_with_key_not_array);
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<google::crypto::tink::Keyset>> keyset =
      (*reader)->Read();
  EXPECT_THAT(keyset, IsOk());
}

TEST_F(JsonKeysetReaderTest, ReadKeysetsWithKeyEntryIsNotObject) {
  const std::string keyset_with_key_not_array = R"(
      {
         "primaryKeyId":42,
         "key":[true]
      })";
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      JsonKeysetReader::New(keyset_with_key_not_array);
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<google::crypto::tink::Keyset>> keyset =
      (*reader)->Read();
  EXPECT_THAT(keyset, Not(IsOk()));
}

TEST_F(JsonKeysetReaderTest, ReadKeysetsWithKeyDataIsNotObject) {
  std::string keyset_with_keydata_not_object = R"(
      {
         "primaryKeyId":42,
         "key":[
            {
               "keyData":true,
               "outputPrefixType":"TINK",
               "keyId": 42,
               "status":"ENABLED"
            }
         ]
      })";
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      JsonKeysetReader::New(keyset_with_keydata_not_object);
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<google::crypto::tink::Keyset>> keyset =
      (*reader)->Read();
  EXPECT_THAT(keyset, Not(IsOk()));
}


}  // namespace
}  // namespace tink
}  // namespace crypto
