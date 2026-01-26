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

#include "tink/binary_keyset_reader.h"

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
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::AddRawKey;
using ::crypto::tink::test::AddTinkKey;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::EncryptedKeyset;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;

class BinaryKeysetReaderTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Keyset::Key key;
    AddTinkKey("some key type", 42, key, KeyStatusType::ENABLED,
               KeyData::SYMMETRIC, &keyset_);
    AddRawKey("some other key type", 711, key, KeyStatusType::ENABLED,
              KeyData::SYMMETRIC, &keyset_);
    keyset_.set_primary_key_id(42);
    good_serialized_keyset_ = keyset_.SerializeAsString();
    bad_serialized_keyset_ = "some weird string";

    encrypted_keyset_.set_encrypted_keyset("some ciphertext with keyset");
    auto keyset_info = encrypted_keyset_.mutable_keyset_info();
    keyset_info->set_primary_key_id(42);
    auto key_info = keyset_info->add_key_info();
    key_info->set_type_url("some type_url");
    key_info->set_key_id(42);
    good_serialized_encrypted_keyset_ = encrypted_keyset_.SerializeAsString();
  }

  EncryptedKeyset encrypted_keyset_;
  Keyset keyset_;
  std::string bad_serialized_keyset_;
  std::string good_serialized_keyset_;
  std::string good_serialized_encrypted_keyset_;
};

TEST_F(BinaryKeysetReaderTest, testReaderCreation) {
  {  // Input stream is null.
    std::unique_ptr<std::istream> null_stream(nullptr);
    auto reader_result = BinaryKeysetReader::New(std::move(null_stream));
    EXPECT_THAT(reader_result, StatusIs(absl::StatusCode::kInvalidArgument));
  }

  {  // Good serialized keyset.
    auto reader_result = BinaryKeysetReader::New(good_serialized_keyset_);
    EXPECT_THAT(reader_result, IsOk());
  }

  {  // Stream with good keyset.
    std::unique_ptr<std::istream> good_keyset_stream(new std::stringstream(
        std::string(good_serialized_keyset_), std::ios_base::in));
    auto reader_result = BinaryKeysetReader::New(std::move(good_keyset_stream));
    EXPECT_THAT(reader_result, IsOk());
  }

  {  // Bad serialized keyset.
    auto reader_result = BinaryKeysetReader::New(bad_serialized_keyset_);
    EXPECT_THAT(reader_result, IsOk());
  }

  {  // Stream with bad keyset.
    std::unique_ptr<std::istream> bad_keyset_stream(new std::stringstream(
        std::string(bad_serialized_keyset_), std::ios_base::in));
    auto reader_result = BinaryKeysetReader::New(std::move(bad_keyset_stream));
    EXPECT_THAT(reader_result, IsOk());
  }
}

TEST_F(BinaryKeysetReaderTest, testReadFromString) {
  {  // Good string.
    auto reader_result = BinaryKeysetReader::New(good_serialized_keyset_);
    EXPECT_THAT(reader_result, IsOk());
    auto reader = std::move(reader_result.value());
    auto read_result = reader->Read();
    EXPECT_THAT(read_result, IsOk());
    auto keyset = std::move(read_result.value());
    EXPECT_EQ(good_serialized_keyset_, keyset->SerializeAsString());
  }

  {  // Bad string.
    auto reader_result = BinaryKeysetReader::New(bad_serialized_keyset_);
    EXPECT_THAT(reader_result, IsOk());
    auto reader = std::move(reader_result.value());
    auto read_result = reader->Read();
    EXPECT_THAT(read_result, StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST_F(BinaryKeysetReaderTest, testReadFromStream) {
  {  // Good stream.
    std::unique_ptr<std::istream> good_keyset_stream(new std::stringstream(
        std::string(good_serialized_keyset_), std::ios_base::in));
    auto reader_result = BinaryKeysetReader::New(std::move(good_keyset_stream));
    EXPECT_THAT(reader_result, IsOk());
    auto reader = std::move(reader_result.value());
    auto read_result = reader->Read();
    EXPECT_THAT(read_result, IsOk());
    auto keyset = std::move(read_result.value());
    EXPECT_EQ(good_serialized_keyset_, keyset->SerializeAsString());
  }

  {  // Bad stream.
    std::unique_ptr<std::istream> bad_keyset_stream(new std::stringstream(
        std::string(bad_serialized_keyset_), std::ios_base::in));
    auto reader_result = BinaryKeysetReader::New(std::move(bad_keyset_stream));
    EXPECT_THAT(reader_result, IsOk());
    auto reader = std::move(reader_result.value());
    auto read_result = reader->Read();
    EXPECT_THAT(read_result, StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST_F(BinaryKeysetReaderTest, testReadEncryptedFromString) {
  {  // Good string.
    auto reader_result =
        BinaryKeysetReader::New(good_serialized_encrypted_keyset_);
    EXPECT_THAT(reader_result, IsOk());
    auto reader = std::move(reader_result.value());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_THAT(read_encrypted_result, IsOk());
    auto encrypted_keyset = std::move(read_encrypted_result.value());
    EXPECT_EQ(good_serialized_encrypted_keyset_,
              encrypted_keyset->SerializeAsString());
  }

  {  // Bad string.
    auto reader_result = BinaryKeysetReader::New(bad_serialized_keyset_);
    EXPECT_THAT(reader_result, IsOk());
    auto reader = std::move(reader_result.value());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_THAT(read_encrypted_result,
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST_F(BinaryKeysetReaderTest, testReadEncryptedFromStream) {
  {  // Good stream.
    std::unique_ptr<std::istream> good_encrypted_keyset_stream(
        new std::stringstream(std::string(good_serialized_encrypted_keyset_),
                              std::ios_base::in));
    auto reader_result =
        BinaryKeysetReader::New(std::move(good_encrypted_keyset_stream));
    EXPECT_THAT(reader_result, IsOk());
    auto reader = std::move(reader_result.value());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_THAT(read_encrypted_result, IsOk());
    auto encrypted_keyset = std::move(read_encrypted_result.value());
    EXPECT_EQ(good_serialized_encrypted_keyset_,
              encrypted_keyset->SerializeAsString());
  }

  {  // Bad string.
    std::unique_ptr<std::istream> bad_keyset_stream(new std::stringstream(
        std::string(bad_serialized_keyset_), std::ios_base::in));
    auto reader_result = BinaryKeysetReader::New(std::move(bad_keyset_stream));
    EXPECT_THAT(reader_result, IsOk());
    auto reader = std::move(reader_result.value());
    auto read_encrypted_result = reader->ReadEncrypted();
    EXPECT_THAT(read_encrypted_result,
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
