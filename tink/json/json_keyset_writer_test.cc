// Copyright 2018 Google Inc.
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

#include "tink/json/json_keyset_writer.h"

#include <iostream>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/binary_keyset_reader.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/json/json_keyset_reader.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/keyset_writer.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_eax.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/aes_gcm_siv.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::AddRawKey;
using ::crypto::tink::test::AddTinkKey;
using ::crypto::tink::test::DummyAead;
using ::crypto::tink::test::IsOk;
using AesEaxKeyProto = ::google::crypto::tink::AesEaxKey;
using AesGcmKeyProto = ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::EncryptedKeyset;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;

namespace {

TEST(JsonKeysetWriterTest, WriterCreation) {
  {  // Input stream is null.
    std::unique_ptr<std::ostream> null_stream(nullptr);
    auto writer_result = JsonKeysetWriter::New(std::move(null_stream));
    EXPECT_FALSE(writer_result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument,
              writer_result.status().code());
  }

  {  // Stream with good keyset.
    std::unique_ptr<std::ostream> destination_stream(new std::stringstream());
    auto writer_result = JsonKeysetWriter::New(std::move(destination_stream));
    EXPECT_TRUE(writer_result.ok()) << writer_result.status();
  }
}

TEST(JsonKeysetWriterTest, WriteAndReadKeyset) {
  Keyset keyset;
  AesGcmKeyProto gcm_key;
  gcm_key.set_key_value("gcm 16-byte key");
  gcm_key.set_version(0);
  AesEaxKeyProto eax_key;
  eax_key.set_key_value("gcm 16-byte key");
  eax_key.set_version(0);
  eax_key.mutable_params()->set_iv_size(16);
  AddTinkKey("type.googleapis.com/google.crypto.tink.AesGcmKey", 42, gcm_key,
             KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset);
  AddRawKey("type.googleapis.com/google.crypto.tink.AesEaxKey", 711, eax_key,
            KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream =
      std::make_unique<std::ostream>(&buffer);
  auto writer_result = JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_THAT(writer_result, IsOk());
  auto writer = std::move(writer_result.value());
  auto status = writer->Write(keyset);
  ASSERT_THAT(status, IsOk());

  auto reader_result = JsonKeysetReader::New(buffer.str());
  ASSERT_THAT(reader_result, IsOk());
  auto reader = std::move(reader_result.value());
  auto read_result = reader->Read();
  ASSERT_THAT(read_result, IsOk());
  EXPECT_THAT((*read_result)->SerializeAsString(),
              Eq(keyset.SerializeAsString()));
}

TEST(JsonKeysetWriterTest, WriteAndReadEncryptedKeyset) {
  EncryptedKeyset encrypted_keyset;
  std::string enc_keyset = "some ciphertext with keyset";
  encrypted_keyset.set_encrypted_keyset(enc_keyset);
  auto keyset_info = encrypted_keyset.mutable_keyset_info();
  keyset_info->set_primary_key_id(42);
  auto key_info = keyset_info->add_key_info();
  key_info->set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  key_info->set_key_id(42);
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_status(KeyStatusType::ENABLED);

  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream =
      std::make_unique<std::ostream>(&buffer);
  auto writer_result = JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_THAT(writer_result, IsOk());
  auto writer = std::move(writer_result.value());
  auto status = writer->Write(encrypted_keyset);
  ASSERT_THAT(status, IsOk());

  auto reader_result = JsonKeysetReader::New(buffer.str());
  ASSERT_THAT(reader_result, IsOk());
  auto reader = std::move(reader_result.value());
  auto read_result = reader->ReadEncrypted();
  ASSERT_THAT(read_result, IsOk());
  EXPECT_THAT((*read_result)->SerializeAsString(),
              Eq(encrypted_keyset.SerializeAsString()));
}

TEST(JsonKeysetWriterTest, WriteKeysetWithDestinationStreamErrors) {
  Keyset keyset;
  AesGcmKeyProto gcm_key;
  gcm_key.set_key_value("gcm 16-byte key");
  gcm_key.set_version(0);
  AddTinkKey("type.googleapis.com/google.crypto.tink.AesGcmKey", 42, gcm_key,
             KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream =
      std::make_unique<std::ostream>(&buffer);
  destination_stream->setstate(std::ostream::badbit);
  auto writer_result = JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_TRUE(writer_result.ok()) << writer_result.status();
  auto writer = std::move(writer_result.value());

  auto status = writer->Write(keyset);
  ASSERT_THAT(status, Not(IsOk()));
}

TEST(JsonKeysetWriterTest, WriteEncryptedKeysetWithDestinationStreamErrors) {
  EncryptedKeyset encrypted_keyset;
  std::string enc_keyset = "some ciphertext with keyset";
  encrypted_keyset.set_encrypted_keyset(enc_keyset);
  auto keyset_info = encrypted_keyset.mutable_keyset_info();
  keyset_info->set_primary_key_id(42);
  auto key_info = keyset_info->add_key_info();
  key_info->set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  key_info->set_key_id(42);
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_status(KeyStatusType::ENABLED);

  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream =
      std::make_unique<std::ostream>(&buffer);
  destination_stream->setstate(std::ostream::badbit);
  auto writer_result = JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_TRUE(writer_result.ok()) << writer_result.status();
  auto writer = std::move(writer_result.value());

  auto status = writer->Write(encrypted_keyset);
  ASSERT_THAT(status, Not(IsOk()));
}

TEST(JsonKeysetWriterTest, WriteLargeKeyId) {
  Keyset keyset;
  AesGcmKeyProto gcm_key;
  gcm_key.set_key_value("gcm 16-byte key");
  gcm_key.set_version(0);
  AddTinkKey("type.googleapis.com/google.crypto.tink.AesGcmKey", 4123456789,
             gcm_key, KeyStatusType::ENABLED, KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(4123456789);  // 4123456789 > 2^31

  std::stringbuf buffer;
  std::unique_ptr<std::ostream> destination_stream =
      std::make_unique<std::ostream>(&buffer);
  auto writer_result = JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_THAT(writer_result, IsOk());
  auto writer = std::move(writer_result.value());
  ASSERT_THAT(writer->Write(keyset), IsOk());
  EXPECT_THAT(buffer.str(), HasSubstr("\"primaryKeyId\":"));
  EXPECT_THAT(buffer.str(), HasSubstr("\"keyId\":"));
  EXPECT_THAT(buffer.str(), HasSubstr("4123456789"));
}

TEST(JsonKeysetWriterTest, ReadValidEncryptedKeyset) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  DummyAead aead("dummy aead 42");
  absl::StatusOr<std::string> keyset_ciphertext =
      aead.Encrypt(keyset.SerializeAsString(), /*associated_data=*/"");
  ASSERT_THAT(keyset_ciphertext.status(), IsOk());

  EncryptedKeyset encrypted_keyset;
  encrypted_keyset.set_encrypted_keyset(*keyset_ciphertext);
  auto* keyset_info = encrypted_keyset.mutable_keyset_info();
  keyset_info->set_primary_key_id(42);
  auto* key_info = keyset_info->add_key_info();
  key_info->set_key_id(42);
  key_info->set_type_url("dummy key type");
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_status(KeyStatusType::ENABLED);
  std::stringbuf buffer;
  auto destination_stream = std::make_unique<std::ostream>(&buffer);
  absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> writer =
      JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_THAT(writer, IsOk());
  absl::Status status = (*writer)->Write(encrypted_keyset);
  ASSERT_THAT(status, IsOk());
  std::string json_serialized_encrypted_keyset = buffer.str();
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      JsonKeysetReader::New(json_serialized_encrypted_keyset);
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::Read(*std::move(reader), aead);
  ASSERT_THAT(handle, IsOk());
  EXPECT_THAT(TestKeysetHandle::GetKeyset(**handle).SerializeAsString(),
              Eq(keyset.SerializeAsString()));
}

TEST(JsonKeysetWriterTest, ReadValidEncryptedKeysetWithoutKeysetInfo) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  DummyAead aead("dummy aead 42");
  absl::StatusOr<std::string> keyset_ciphertext =
      aead.Encrypt(keyset.SerializeAsString(), /*associated_data=*/"");
  ASSERT_THAT(keyset_ciphertext.status(), IsOk());

  EncryptedKeyset encrypted_keyset;
  encrypted_keyset.set_encrypted_keyset(*keyset_ciphertext);
  std::stringbuf buffer;
  auto destination_stream = std::make_unique<std::ostream>(&buffer);
  absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> writer =
      JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_THAT(writer, IsOk());
  absl::Status status = (*writer)->Write(encrypted_keyset);
  ASSERT_THAT(status, IsOk());
  std::string json_serialized_encrypted_keyset = buffer.str();

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      JsonKeysetReader::New(json_serialized_encrypted_keyset);
  ASSERT_THAT(reader, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::Read(*std::move(reader), aead);
  ASSERT_THAT(handle, IsOk());
  EXPECT_EQ(keyset.SerializeAsString(),
            TestKeysetHandle::GetKeyset(**handle).SerializeAsString());
}

TEST(JsonKeysetWriterTest, WrongAeadCannotReadEncryptedKeyset) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  DummyAead aead("dummy aead 42");
  absl::StatusOr<std::string> keyset_ciphertext =
      aead.Encrypt(keyset.SerializeAsString(), /*associated_data=*/"");
  ASSERT_THAT(keyset_ciphertext, IsOk());
  EncryptedKeyset encrypted_keyset;
  encrypted_keyset.set_encrypted_keyset(*keyset_ciphertext);
  std::stringbuf buffer;
  auto destination_stream = std::make_unique<std::ostream>(&buffer);
  absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> writer =
      JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_THAT(writer, IsOk());
  absl::Status status = (*writer)->Write(encrypted_keyset);
  ASSERT_THAT(status, IsOk());
  std::string json_serialized_encrypted_keyset = buffer.str();

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      JsonKeysetReader::New(json_serialized_encrypted_keyset);
  ASSERT_THAT(reader, IsOk());
  DummyAead wrong_aead("wrong aead");
  absl::StatusOr<std::unique_ptr<KeysetHandle>> decrypted_keyset =
      KeysetHandle::Read(*std::move(reader), wrong_aead);
  ASSERT_THAT(decrypted_keyset.status(), Not(IsOk()));
}

TEST(JsonKeysetWriterTest, CiphertextDoesNotContainKeyset) {
  DummyAead aead("dummy aead 42");
  absl::StatusOr<std::string> keyset_ciphertext =
      aead.Encrypt("not a serialized keyset", /*associated_data=*/"");
  ASSERT_THAT(keyset_ciphertext, IsOk());
  EncryptedKeyset encrypted_keyset;
  encrypted_keyset.set_encrypted_keyset(*keyset_ciphertext);

  std::stringbuf buffer;
  auto destination_stream = std::make_unique<std::ostream>(&buffer);
  absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> writer =
      JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_THAT(writer, IsOk());
  absl::Status status = (*writer)->Write(encrypted_keyset);
  ASSERT_THAT(status, IsOk());
  std::string json_serialized_encrypted_keyset = buffer.str();

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      JsonKeysetReader::New(json_serialized_encrypted_keyset);
  absl::StatusOr<std::unique_ptr<KeysetHandle>> decrypted_keyset =
      KeysetHandle::Read(*std::move(reader), aead);
  ASSERT_THAT(decrypted_keyset.status(), Not(IsOk()));
}

TEST(JsonKeysetWriterTest, InvalidCiphertextInEncryptedKeyset) {
  DummyAead aead("dummy aead 42");
  std::string keyset_ciphertext = "totally wrong ciphertext";
  EncryptedKeyset encrypted_keyset;
  encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);

  std::stringbuf buffer;
  auto destination_stream = std::make_unique<std::ostream>(&buffer);
  absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> writer =
      JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_THAT(writer, IsOk());
  absl::Status status = (*writer)->Write(encrypted_keyset);
  ASSERT_THAT(status, IsOk());
  std::string json_serialized_encrypted_keyset = buffer.str();

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      JsonKeysetReader::New(json_serialized_encrypted_keyset);
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset =
      KeysetHandle::Read(*std::move(reader), aead);
  EXPECT_THAT(keyset.status(), Not(IsOk()));
}

TEST(JsonKeysetWriterTest, WriteEncryptedKeyset) {
  // Prepare a valid keyset handle
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      BinaryKeysetReader::New(keyset.SerializeAsString());
  ASSERT_THAT(reader.status(), IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      CleartextKeysetHandle::Read(*std::move(reader));
  ASSERT_THAT(keyset_handle.status(), IsOk());

  // Prepare a keyset writer.
  DummyAead aead("dummy aead 42");
  std::stringbuf buffer;
  auto destination_stream = std::make_unique<std::ostream>(&buffer);
  absl::StatusOr<std::unique_ptr<KeysetWriter>> writer =
      JsonKeysetWriter::New(std::move(destination_stream));
  ASSERT_THAT(writer.status(), IsOk());

  // Write the keyset handle and check the result.
  ASSERT_THAT((*keyset_handle)->Write(writer->get(), aead), IsOk());
  absl::StatusOr<std::unique_ptr<KeysetReader>> json_reader =
      JsonKeysetReader::New(buffer.str());
  ASSERT_THAT(json_reader.status(), IsOk());
  absl::StatusOr<std::unique_ptr<google::crypto::tink::EncryptedKeyset>>
      read_encrypted_result = (*json_reader)->ReadEncrypted();
  ASSERT_THAT(read_encrypted_result.status(), IsOk());

  absl::StatusOr<std::string> decrypted_keyset =
      aead.Decrypt((*read_encrypted_result)->encrypted_keyset(),
                   /*associated_data=*/"");
  ASSERT_THAT(decrypted_keyset.status(), IsOk());
  ASSERT_THAT(*decrypted_keyset, keyset.SerializeAsString());
}

TEST(JsonKeysetWriterTest, WriteEncryptedKeysetWithNullWriter) {
  // Prepare a valid keyset handle
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      BinaryKeysetReader::New(keyset.SerializeAsString());
  ASSERT_THAT(reader.status(), IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      CleartextKeysetHandle::Read(*std::move(reader));
  ASSERT_THAT(keyset_handle.status(), IsOk());

  DummyAead aead("dummy aead 42");

  absl::Status write_status = (*keyset_handle)->Write(nullptr, aead);
  EXPECT_THAT(write_status, Not(IsOk()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
