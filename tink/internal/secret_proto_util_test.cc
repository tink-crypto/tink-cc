// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/internal/secret_proto_util.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/internal/secret_buffer.h"
#include "tink/secret_data.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsEmpty;

TEST(SecretProtoUtilTest, SerializeNonEmptyProto) {
  KeyData key_data;
  key_data.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  key_data.set_value("secret_key_bytes");
  key_data.set_key_material_type(KeyData::SYMMETRIC);

  absl::StatusOr<SecretBuffer> serialized =
      SerializeProtoAsSecretBuffer(key_data);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(serialized->AsStringView(), Eq(key_data.SerializeAsString()));

  KeyData parsed;
  ASSERT_TRUE(parsed.ParseFromString(serialized->AsStringView()));
  EXPECT_THAT(parsed.type_url(), Eq(key_data.type_url()));
  EXPECT_THAT(parsed.value(), Eq(key_data.value()));
  EXPECT_THAT(parsed.key_material_type(), Eq(key_data.key_material_type()));
}

TEST(SecretProtoUtilTest, SerializeNestedProto) {
  Keyset keyset;
  keyset.set_primary_key_id(42);
  Keyset::Key* first_key = keyset.add_key();
  first_key->mutable_key_data()->set_type_url(
      "type.googleapis.com/google.crypto.tink.AesGcmKey");
  first_key->mutable_key_data()->set_value("first_secret_key_material");
  first_key->mutable_key_data()->set_key_material_type(KeyData::SYMMETRIC);
  first_key->set_status(KeyStatusType::ENABLED);
  first_key->set_key_id(42);
  first_key->set_output_prefix_type(OutputPrefixType::TINK);

  Keyset::Key* second_key = keyset.add_key();
  second_key->mutable_key_data()->set_type_url(
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey");
  second_key->mutable_key_data()->set_value("second_secret_key_material");
  second_key->mutable_key_data()->set_key_material_type(
      KeyData::ASYMMETRIC_PRIVATE);
  second_key->set_status(KeyStatusType::DISABLED);
  second_key->set_key_id(7);
  second_key->set_output_prefix_type(OutputPrefixType::RAW);

  absl::StatusOr<SecretBuffer> serialized =
      SerializeProtoAsSecretBuffer(keyset);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(serialized->AsStringView(), Eq(keyset.SerializeAsString()));

  Keyset parsed;
  ASSERT_TRUE(parsed.ParseFromString(serialized->AsStringView()));
  EXPECT_THAT(parsed.primary_key_id(), Eq(42));
  ASSERT_THAT(parsed.key_size(), Eq(2));
  EXPECT_THAT(parsed.key(0).key_data().value(),
              Eq("first_secret_key_material"));
  EXPECT_THAT(parsed.key(1).key_data().value(),
              Eq("second_secret_key_material"));
}

TEST(SecretProtoUtilTest, SerializeEmptyProto) {
  KeyData empty_key_data;

  absl::StatusOr<SecretBuffer> serialized =
      SerializeProtoAsSecretBuffer(empty_key_data);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(serialized->size(), Eq(0));
  EXPECT_THAT(serialized->AsStringView(), IsEmpty());
}

TEST(SecretProtoUtilTest, SerializeLargeProto) {
  KeyData key_data;
  key_data.set_type_url("type.googleapis.com/google.crypto.tink.RsaSsaPssKey");
  key_data.set_value(std::string(8192, '\x5a'));
  key_data.set_key_material_type(KeyData::ASYMMETRIC_PRIVATE);

  absl::StatusOr<SecretBuffer> serialized =
      SerializeProtoAsSecretBuffer(key_data);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(serialized->AsStringView(), Eq(key_data.SerializeAsString()));

  KeyData parsed;
  ASSERT_TRUE(parsed.ParseFromString(serialized->AsStringView()));
  EXPECT_THAT(parsed.value(), Eq(key_data.value()));
}

TEST(SecretProtoUtilTest, MoveIntoSecretDataPreservesBytesAndCrc) {
  KeyData key_data;
  key_data.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  key_data.set_value("secret_payload_for_crc_check");
  key_data.set_key_material_type(KeyData::SYMMETRIC);

  absl::StatusOr<SecretBuffer> serialized =
      SerializeProtoAsSecretBuffer(key_data);
  ASSERT_THAT(serialized, IsOk());

  SecretData secret_data(std::move(*serialized));
  EXPECT_THAT(secret_data.AsStringView(), Eq(key_data.SerializeAsString()));
  EXPECT_THAT(secret_data.ValidateCrc32c(), IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
