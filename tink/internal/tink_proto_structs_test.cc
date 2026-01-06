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
  const std::string serialized_hmac_key_template =
      absl::StrCat(proto_testing::FieldWithNumber(1).IsString("type_url"),
                   proto_testing::FieldWithNumber(2).IsString("value"),
                   proto_testing::FieldWithNumber(3).IsVarint(
                       static_cast<int>(OutputPrefixTypeEnum::kTink)));

  KeyTemplateTP key_template;
  ASSERT_THAT(key_template.ParseFromString(serialized_hmac_key_template),
              IsTrue());
  EXPECT_THAT(key_template.type_url(), Eq("type_url"));
  EXPECT_THAT(key_template.value(), Eq("value"));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(OutputPrefixTypeEnum::kTink));
}

TEST(KeyTemplateTPTest, ParseKeyTemplateTPInvalid) {
  KeyTemplateTP params;
  EXPECT_THAT(params.ParseFromString("invalid"), IsFalse());
}

TEST(KeyTemplateTPTest, ParseKeyTemplateTPInvalidOutputPrefixType) {
  const std::string serialized_hmac_key_template =
      absl::StrCat(proto_testing::FieldWithNumber(1).IsString("type_url"),
                   proto_testing::FieldWithNumber(2).IsString("value"),
                   proto_testing::FieldWithNumber(3).IsVarint(6));
  KeyTemplateTP params;
  EXPECT_THAT(params.ParseFromString(serialized_hmac_key_template), IsTrue());
  EXPECT_THAT(params.output_prefix_type(),
              Eq(OutputPrefixTypeEnum::kUnknownPrefix));
}

TEST(KeyTemplateTPTest, SerializeKeyTemplateTP) {
  KeyTemplateTP key_template;
  key_template.set_output_prefix_type(OutputPrefixTypeEnum::kTink);
  key_template.set_type_url("type_url");
  key_template.set_value("value");

  auto serialized_hmac_key_template = key_template.SerializeAsSecretData();
  EXPECT_THAT(
      util::SecretDataAsStringView(serialized_hmac_key_template),
      Eq(absl::StrCat(proto_testing::FieldWithNumber(1).IsString("type_url"),
                      proto_testing::FieldWithNumber(2).IsString("value"),
                      proto_testing::FieldWithNumber(3).IsVarint(
                          static_cast<int>(OutputPrefixTypeEnum::kTink)))));
}

TEST(KeyDataTPTest, ParseKeyDataTP) {
  const std::string serialized_hmac_key_data = absl::StrCat(
      proto_testing::FieldWithNumber(1).IsString("type_url"),
      proto_testing::FieldWithNumber(2).IsString("key_material"),
      proto_testing::FieldWithNumber(3).IsVarint(
          static_cast<int>(KeyMaterialTypeEnum::kAsymmetricPrivate)));

  KeyDataTP key_data;
  ASSERT_THAT(key_data.ParseFromString(serialized_hmac_key_data), IsTrue());
  EXPECT_THAT(key_data.type_url(), Eq("type_url"));
  EXPECT_THAT(util::SecretDataAsStringView(key_data.value()),
              Eq("key_material"));
  EXPECT_THAT(key_data.key_material_type(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPrivate));
}

TEST(KeyDataTPTest, ParseKeyDataTPInvalid) {
  KeyDataTP params;
  EXPECT_THAT(params.ParseFromString("invalid"), IsFalse());
}

TEST(KeyDataTPTest, ParseKeyDataTPInvalidKeyMaterialType) {
  const std::string serialized_hmac_key_data =
      absl::StrCat(proto_testing::FieldWithNumber(1).IsString("type_url"),
                   proto_testing::FieldWithNumber(2).IsString("key_material"),
                   proto_testing::FieldWithNumber(3).IsVarint(5));
  KeyDataTP params;
  EXPECT_THAT(params.ParseFromString(serialized_hmac_key_data), IsTrue());
  EXPECT_THAT(params.key_material_type(),
              Eq(KeyMaterialTypeEnum::kUnknownKeyMaterial));
}

TEST(KeyDataTPTest, SerializeKeyDataTP) {
  KeyDataTP key_data;
  key_data.set_type_url("type_url");
  key_data.set_value("value");
  key_data.set_key_material_type(KeyMaterialTypeEnum::kAsymmetricPrivate);

  auto serialized_hmac_key_data = key_data.SerializeAsSecretData();
  EXPECT_THAT(util::SecretDataAsStringView(serialized_hmac_key_data),
              Eq(absl::StrCat(
                  proto_testing::FieldWithNumber(1).IsString("type_url"),
                  proto_testing::FieldWithNumber(2).IsString("value"),
                  proto_testing::FieldWithNumber(3).IsVarint(static_cast<int>(
                      KeyMaterialTypeEnum::kAsymmetricPrivate)))));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
