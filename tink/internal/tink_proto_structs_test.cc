// Copyright 2025 Google LLC
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
#include "tink/internal/tink_proto_structs.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "tink/internal/testing/field_with_number.h"
#include "tink/util/secret_data.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;

TEST(KeyTemplateTPTest, ParseKeyTemplateTP) {
  const std::string serialized_hmac_key_template = absl::StrCat(
      proto_testing::FieldWithNumber(1).IsString("type_url"),
      proto_testing::FieldWithNumber(2).IsString("value"),
      proto_testing::FieldWithNumber(3).IsVarint(static_cast<int>(
          google::crypto::tink::internal::OutputPrefixTypeTP::kTink)));

  google::crypto::tink::internal::KeyTemplateTP key_template;
  ASSERT_THAT(key_template.ParseFromString(serialized_hmac_key_template),
              IsTrue());
  EXPECT_THAT(key_template.type_url(), Eq("type_url"));
  EXPECT_THAT(key_template.value(), Eq("value"));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(google::crypto::tink::internal::OutputPrefixTypeTP::kTink));
}

TEST(KeyTemplateTPTest, ParseKeyTemplateTPInvalid) {
  google::crypto::tink::internal::KeyTemplateTP params;
  EXPECT_THAT(params.ParseFromString("invalid"), IsFalse());
}

TEST(KeyTemplateTPTest, ParseKeyTemplateTPInvalidOutputPrefixType) {
  const std::string serialized_hmac_key_template =
      absl::StrCat(proto_testing::FieldWithNumber(1).IsString("type_url"),
                   proto_testing::FieldWithNumber(2).IsString("value"),
                   proto_testing::FieldWithNumber(3).IsVarint(6));
  google::crypto::tink::internal::KeyTemplateTP params;
  EXPECT_THAT(params.ParseFromString(serialized_hmac_key_template), IsTrue());
  EXPECT_THAT(
      params.output_prefix_type(),
      Eq(google::crypto::tink::internal::OutputPrefixTypeTP::kUnknownPrefix));
}

TEST(KeyTemplateTPTest, SerializeKeyTemplateTP) {
  google::crypto::tink::internal::KeyTemplateTP key_template;
  key_template.set_output_prefix_type(
      google::crypto::tink::internal::OutputPrefixTypeTP::kTink);
  key_template.set_type_url("type_url");
  key_template.set_value("value");

  auto serialized_hmac_key_template = key_template.SerializeAsSecretData();
  EXPECT_THAT(
      util::SecretDataAsStringView(serialized_hmac_key_template),
      Eq(absl::StrCat(
          proto_testing::FieldWithNumber(1).IsString("type_url"),
          proto_testing::FieldWithNumber(2).IsString("value"),
          proto_testing::FieldWithNumber(3).IsVarint(static_cast<int>(
              google::crypto::tink::internal::OutputPrefixTypeTP::kTink)))));
}

TEST(KeyDataTPTest, ParseKeyDataTP) {
  const std::string serialized_hmac_key_data =
      absl::StrCat(proto_testing::FieldWithNumber(1).IsString("type_url"),
                   proto_testing::FieldWithNumber(2).IsString("key_material"),
                   proto_testing::FieldWithNumber(3).IsVarint(static_cast<int>(
                       google::crypto::tink::internal::KeyDataTP::
                           KeyMaterialTypeTP::kAsymmetricPrivate)));

  google::crypto::tink::internal::KeyDataTP key_data;
  ASSERT_THAT(key_data.ParseFromString(serialized_hmac_key_data), IsTrue());
  EXPECT_THAT(key_data.type_url(), Eq("type_url"));
  EXPECT_THAT(util::SecretDataAsStringView(key_data.value()),
              Eq("key_material"));
  EXPECT_THAT(key_data.key_material_type(),
              Eq(google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
                     kAsymmetricPrivate));
}

TEST(KeyDataTPTest, ParseKeyDataTPInvalid) {
  google::crypto::tink::internal::KeyDataTP params;
  EXPECT_THAT(params.ParseFromString("invalid"), IsFalse());
}

TEST(KeyDataTPTest, ParseKeyDataTPInvalidKeyMaterialType) {
  const std::string serialized_hmac_key_data =
      absl::StrCat(proto_testing::FieldWithNumber(1).IsString("type_url"),
                   proto_testing::FieldWithNumber(2).IsString("key_material"),
                   proto_testing::FieldWithNumber(3).IsVarint(5));
  google::crypto::tink::internal::KeyDataTP params;
  EXPECT_THAT(params.ParseFromString(serialized_hmac_key_data), IsTrue());
  EXPECT_THAT(params.key_material_type(),
              Eq(google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
                     kUnknownKeymaterial));
}

TEST(KeyDataTPTest, SerializeKeyDataTP) {
  google::crypto::tink::internal::KeyDataTP key_data;
  key_data.set_type_url("type_url");
  key_data.set_value(util::SecretDataFromStringView("value"));
  key_data.set_key_material_type(google::crypto::tink::internal::KeyDataTP::
                                     KeyMaterialTypeTP::kAsymmetricPrivate);

  auto serialized_hmac_key_data = key_data.SerializeAsSecretData();
  EXPECT_THAT(util::SecretDataAsStringView(serialized_hmac_key_data),
              Eq(absl::StrCat(
                  proto_testing::FieldWithNumber(1).IsString("type_url"),
                  proto_testing::FieldWithNumber(2).IsString("value"),
                  proto_testing::FieldWithNumber(3).IsVarint(static_cast<int>(
                      google::crypto::tink::internal::KeyDataTP::
                          KeyMaterialTypeTP::kAsymmetricPrivate)))));
}

TEST(KeyTPTest, ParseKeyData) {
  const std::string serialized_key =
      absl::StrCat(proto_testing::FieldWithNumber(1).IsString(absl::StrCat(
          proto_testing::FieldWithNumber(1).IsString("type_url"),
          proto_testing::FieldWithNumber(2).IsString("value"),
          proto_testing::FieldWithNumber(3).IsVarint(
              static_cast<int>(google::crypto::tink::internal::KeyDataTP::
                                   KeyMaterialTypeTP::kSymmetric)))));
  google::crypto::tink::internal::KeysetTP::KeyTP key;
  ASSERT_THAT(key.ParseFromString(serialized_key), IsTrue());
  EXPECT_THAT(key.key_data().type_url(), Eq("type_url"));
  EXPECT_THAT(util::SecretDataAsStringView(key.key_data().value()),
              Eq("value"));
  EXPECT_THAT(key.key_data().key_material_type(),
              Eq(google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
                     kSymmetric));
}

TEST(KeyTPTest, ParseStatus) {
  const std::string serialized_key =
      proto_testing::FieldWithNumber(2).IsVarint(static_cast<int>(
          google::crypto::tink::internal::KeyStatusTypeTP::kEnabled));
  google::crypto::tink::internal::KeysetTP::KeyTP key;
  ASSERT_THAT(key.ParseFromString(serialized_key), IsTrue());
  EXPECT_THAT(key.status(),
              Eq(google::crypto::tink::internal::KeyStatusTypeTP::kEnabled));
}

TEST(KeyTPTest, ParseKeyId) {
  const std::string serialized_key =
      proto_testing::FieldWithNumber(3).IsVarint(12345);
  google::crypto::tink::internal::KeysetTP::KeyTP key;
  ASSERT_THAT(key.ParseFromString(serialized_key), IsTrue());
  EXPECT_THAT(key.key_id(), Eq(12345));
}

TEST(KeyTPTest, ParseOutputPrefixType) {
  const std::string serialized_key =
      proto_testing::FieldWithNumber(4).IsVarint(static_cast<int>(
          google::crypto::tink::internal::OutputPrefixTypeTP::kTink));
  google::crypto::tink::internal::KeysetTP::KeyTP key;
  ASSERT_THAT(key.ParseFromString(serialized_key), IsTrue());
  EXPECT_THAT(key.output_prefix_type(),
              Eq(google::crypto::tink::internal::OutputPrefixTypeTP::kTink));
}

TEST(KeyTPTest, RoundTrip) {
  google::crypto::tink::internal::KeysetTP::KeyTP key;
  key.mutable_key_data()->set_type_url("type_url");
  key.mutable_key_data()->set_value(util::SecretDataFromStringView("value"));
  key.mutable_key_data()->set_key_material_type(
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::kSymmetric);
  key.set_status(google::crypto::tink::internal::KeyStatusTypeTP::kEnabled);
  key.set_key_id(12345);
  key.set_output_prefix_type(
      google::crypto::tink::internal::OutputPrefixTypeTP::kTink);

  auto serialized = key.SerializeAsSecretData();
  google::crypto::tink::internal::KeysetTP::KeyTP key2;
  ASSERT_THAT(key2.ParseFromString(util::SecretDataAsStringView(serialized)),
              IsTrue());

  EXPECT_THAT(key2.key_data().type_url(), Eq("type_url"));
  EXPECT_THAT(util::SecretDataAsStringView(key2.key_data().value()),
              Eq("value"));
  EXPECT_THAT(key2.key_data().key_material_type(),
              Eq(google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
                     kSymmetric));
  EXPECT_THAT(key2.status(),
              Eq(google::crypto::tink::internal::KeyStatusTypeTP::kEnabled));
  EXPECT_THAT(key2.key_id(), Eq(12345));
  EXPECT_THAT(key2.output_prefix_type(),
              Eq(google::crypto::tink::internal::OutputPrefixTypeTP::kTink));
}

TEST(KeysetTPTest, ParsePrimaryKeyId) {
  const std::string serialized_keyset =
      proto_testing::FieldWithNumber(1).IsVarint(12345);
  google::crypto::tink::internal::KeysetTP keyset;
  ASSERT_THAT(keyset.ParseFromString(serialized_keyset), IsTrue());
  EXPECT_THAT(keyset.primary_key_id(), Eq(12345));
}

TEST(KeysetTPTest, ParseKey) {
  const std::string serialized_keyset =
      absl::StrCat(proto_testing::FieldWithNumber(2).IsString(
                       proto_testing::FieldWithNumber(3).IsVarint(1)),
                   proto_testing::FieldWithNumber(2).IsString(
                       proto_testing::FieldWithNumber(3).IsVarint(2)));
  google::crypto::tink::internal::KeysetTP keyset;
  ASSERT_THAT(keyset.ParseFromString(serialized_keyset), IsTrue());
  ASSERT_THAT(keyset.key_size(), Eq(2));
  EXPECT_THAT(keyset.key(0).key_id(), Eq(1));
  EXPECT_THAT(keyset.key(1).key_id(), Eq(2));
}

TEST(KeysetTPTest, RoundTrip) {
  google::crypto::tink::internal::KeysetTP keyset;
  keyset.set_primary_key_id(12345);
  google::crypto::tink::internal::KeysetTP::KeyTP* key1 = keyset.add_key();
  key1->set_key_id(1);
  key1->set_status(google::crypto::tink::internal::KeyStatusTypeTP::kEnabled);
  google::crypto::tink::internal::KeysetTP::KeyTP* key2 = keyset.add_key();
  key2->set_key_id(2);
  key2->set_status(google::crypto::tink::internal::KeyStatusTypeTP::kDisabled);

  auto serialized = keyset.SerializeAsSecretData();
  google::crypto::tink::internal::KeysetTP keyset2;
  ASSERT_THAT(keyset2.ParseFromString(util::SecretDataAsStringView(serialized)),
              IsTrue());

  EXPECT_THAT(keyset2.primary_key_id(), Eq(12345));
  ASSERT_THAT(keyset2.key_size(), Eq(2));
  EXPECT_THAT(keyset2.key(0).key_id(), Eq(1));
  EXPECT_THAT(keyset2.key(0).status(),
              Eq(google::crypto::tink::internal::KeyStatusTypeTP::kEnabled));
  EXPECT_THAT(keyset2.key(1).key_id(), Eq(2));
  EXPECT_THAT(keyset2.key(1).status(),
              Eq(google::crypto::tink::internal::KeyStatusTypeTP::kDisabled));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
