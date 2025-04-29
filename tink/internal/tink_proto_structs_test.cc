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
#include <string_view>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;

std::string GetSerializedKeyTemplate(std::string_view type_url,
                                     std::string_view value,
                                     OutputPrefixType output_prefix_type) {
  KeyTemplate key_template;
  key_template.set_type_url(type_url);
  key_template.set_value(value);
  key_template.set_output_prefix_type(output_prefix_type);
  return key_template.SerializeAsString();
}

std::string GetSerializedKeyData(std::string_view type_url,
                                 std::string_view value,
                                 KeyData::KeyMaterialType key_material_type) {
  KeyData key_data;
  key_data.set_type_url(type_url);
  key_data.set_value(value);
  key_data.set_key_material_type(key_material_type);
  return key_data.SerializeAsString();
}

TEST(TinkProtoStructsTest, ParseKeyTemplateStruct) {
  absl::StatusOr<KeyTemplateStruct> key_template_struct =
      KeyTemplateStruct::GetParser().Parse(GetSerializedKeyTemplate(
          "type_url", "value", OutputPrefixType::TINK));
  ASSERT_THAT(key_template_struct, IsOk());

  EXPECT_THAT(key_template_struct->type_url, Eq("type_url"));
  EXPECT_THAT(key_template_struct->value, Eq("value"));
  EXPECT_THAT(key_template_struct->output_prefix_type,
              Eq(OutputPrefixTypeEnum::kTink));
}

TEST(TinkProtoStructsTest, SerializeKeyTemplateStruct) {
  KeyTemplateStruct key_template_struct;
  key_template_struct.type_url = "type_url",
  key_template_struct.value = "value",
  key_template_struct.output_prefix_type = OutputPrefixTypeEnum::kTink;
  absl::StatusOr<std::string> serialized_key_template =
      KeyTemplateStruct::GetParser().SerializeIntoString(key_template_struct);
  ASSERT_THAT(serialized_key_template, IsOk());

  KeyTemplate key_template;
  key_template.ParseFromString(*serialized_key_template);
  EXPECT_THAT(key_template.type_url(), Eq("type_url"));
  EXPECT_THAT(key_template.value(), Eq("value"));
  EXPECT_THAT(key_template.output_prefix_type(), Eq(OutputPrefixType::TINK));
}

TEST(TinkProtoStructsTest, ParseKeyDataStruct) {
  absl::StatusOr<KeyDataStruct> key_data_struct =
      KeyDataStruct::GetParser().Parse(
          GetSerializedKeyData("type_url", "value", KeyData::SYMMETRIC));
  ASSERT_THAT(key_data_struct, IsOk());

  EXPECT_THAT(key_data_struct->type_url, Eq("type_url"));
  EXPECT_THAT(util::SecretDataAsStringView(key_data_struct->value),
              Eq("value"));
  EXPECT_THAT(key_data_struct->key_material_type,
              Eq(KeyMaterialTypeEnum::kSymmetric));
}

TEST(TinkProtoStructsTest, SerializeKeyDataStruct) {
  KeyDataStruct key_data_struct;
  key_data_struct.type_url = "type_url";
  key_data_struct.value = util::SecretDataFromStringView("value");
  key_data_struct.key_material_type = KeyMaterialTypeEnum::kSymmetric;
  absl::StatusOr<SecretData> serialized_key_data =
      KeyDataStruct::GetParser().SerializeIntoSecretData(key_data_struct);
  ASSERT_THAT(serialized_key_data, IsOk());

  KeyData key_data;
  key_data.ParseFromString(util::SecretDataAsStringView(*serialized_key_data));
  EXPECT_THAT(key_data.type_url(), Eq("type_url"));
  EXPECT_THAT(key_data.value(), Eq("value"));
  EXPECT_THAT(key_data.key_material_type(), Eq(KeyData::SYMMETRIC));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
