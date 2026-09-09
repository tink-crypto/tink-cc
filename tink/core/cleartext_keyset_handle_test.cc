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

#include "tink/cleartext_keyset_handle.h"

#include <istream>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "google/protobuf/util/message_differencer.h"
#include "tink/binary_keyset_reader.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::test::AddRawKey;
using ::crypto::tink::test::AddTinkKey;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::protobuf::util::MessageDifferencer;

class CleartextKeysetHandleTest : public ::testing::Test {
 protected:
};

TEST_F(CleartextKeysetHandleTest, testRead) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);
  {  // Reader that reads a valid keyset.
    auto reader =
        std::move(BinaryKeysetReader::New(keyset.SerializeAsString()).value());
    auto result = CleartextKeysetHandle::Read(std::move(reader));
    EXPECT_THAT(result, IsOk());
    auto handle = std::move(result.value());
    EXPECT_EQ(keyset.SerializeAsString(),
              TestKeysetHandle::GetKeyset(*handle).SerializeAsString());
  }

  {  // Reader that fails upon read.
    auto reader =
        std::move(BinaryKeysetReader::New("invalid serialized keyset").value());
    auto result = CleartextKeysetHandle::Read(std::move(reader));
    EXPECT_THAT(result, StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST_F(CleartextKeysetHandleTest, testWrite) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  auto handle = TestKeysetHandle::GetKeysetHandle(keyset);

  std::stringbuf buffer;
  auto destination_stream = std::make_unique<std::ostream>(&buffer);
  auto writer =
      test::DummyKeysetWriter::New(std::move(destination_stream)).value();

  // Write a valid keyset.
  EXPECT_EQ(CleartextKeysetHandle::Write(writer.get(), *(handle.get())),
            absl::OkStatus());

  // Null writer.
  EXPECT_NE(CleartextKeysetHandle::Write(nullptr, *(handle.get())),
            absl::OkStatus());
}

TEST_F(CleartextKeysetHandleTest, GetKeysetHandleOrError) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  absl::StatusOr<KeysetHandle> handle =
      CleartextKeysetHandle::GetKeysetHandleOrError(
          keyset, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(handle, IsOk());
  std::string differences;
  MessageDifferencer message_differencer;
  message_differencer.ReportDifferencesToString(&differences);
  EXPECT_TRUE(message_differencer.Compare(
      CleartextKeysetHandle::GetKeyset(*handle), keyset))
      << differences;
}

TEST_F(CleartextKeysetHandleTest, GetKeysetOrError) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  absl::StatusOr<KeysetHandle> handle =
      CleartextKeysetHandle::GetKeysetHandleOrError(
          keyset, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<Keyset> got_keyset = CleartextKeysetHandle::GetKeysetOrError(
      *handle, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(got_keyset, IsOk());
  std::string differences;
  MessageDifferencer message_differencer;
  message_differencer.ReportDifferencesToString(&differences);
  EXPECT_TRUE(message_differencer.Compare(*got_keyset, keyset)) << differences;
}

TEST_F(CleartextKeysetHandleTest, GetKeysetHandle) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  std::unique_ptr<KeysetHandle> handle =
      CleartextKeysetHandle::GetKeysetHandle(keyset);
  ASSERT_NE(handle, nullptr);
  std::string differences;
  MessageDifferencer message_differencer;
  message_differencer.ReportDifferencesToString(&differences);
  EXPECT_TRUE(message_differencer.Compare(
      CleartextKeysetHandle::GetKeyset(*handle), keyset))
      << differences;
}

TEST_F(CleartextKeysetHandleTest, GetKeyset) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  absl::StatusOr<KeysetHandle> handle =
      CleartextKeysetHandle::GetKeysetHandleOrError(
          keyset, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(handle, IsOk());
  Keyset got_keyset = CleartextKeysetHandle::GetKeyset(*handle);
  std::string differences;
  MessageDifferencer message_differencer;
  message_differencer.ReportDifferencesToString(&differences);
  EXPECT_TRUE(message_differencer.Compare(got_keyset, keyset)) << differences;
}

}  // namespace
}  // namespace tink
}  // namespace crypto
