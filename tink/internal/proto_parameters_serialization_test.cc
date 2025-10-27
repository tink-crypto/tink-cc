// Copyright 2022 Google LLC
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

#include "tink/internal/proto_parameters_serialization.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/util/test_matchers.h"
#include "proto/test_proto.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::TestProto;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsFalse;
using ::testing::IsTrue;

class ProtoParametersSerializationTest : public ::testing::Test {
 protected:
  bool Equals(ProtoParametersSerialization serialization,
              ProtoParametersSerialization other) {
    return serialization.EqualsWithPotentialFalseNegatives(other);
  }
};

TEST_F(ProtoParametersSerializationTest, CreateFromIndividualComponents) {
  TestProto test_proto;
  test_proto.set_num(12345);
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create("type_url",
                                           OutputPrefixTypeEnum::kRaw,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(serialization.status(), IsOk());

  EXPECT_THAT(serialization->ObjectIdentifier(), "type_url");
  const KeyTemplateStruct& key_template = serialization->GetKeyTemplateStruct();
  EXPECT_THAT(key_template.type_url, "type_url");
  EXPECT_THAT(key_template.output_prefix_type, OutputPrefixTypeEnum::kRaw);
  EXPECT_THAT(key_template.value, test_proto.SerializeAsString());
  TestProto parsed_proto;
  parsed_proto.ParseFromString(key_template.value);
  EXPECT_THAT(parsed_proto.num(), Eq(12345));
}

TEST_F(ProtoParametersSerializationTest,
       CreateFromIndividualComponentsWithNonPrintableAsciiTypeURLFails) {
  TestProto test_proto;
  test_proto.set_num(12345);
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create("type_url\x01",
                                           OutputPrefixTypeEnum::kRaw,
                                           test_proto.SerializeAsString());

  EXPECT_THAT(
      serialization.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Non-printable ASCII character in type URL.")));
}

TEST_F(ProtoParametersSerializationTest, CreateFromKeyTemplate) {
  TestProto test_proto;
  test_proto.set_num(12345);
  KeyTemplate key_template;
  key_template.set_value(test_proto.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  key_template.set_type_url("type_url");
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(key_template);
  ASSERT_THAT(serialization.status(), IsOk());

  EXPECT_THAT(serialization->ObjectIdentifier(), "type_url");
  const KeyTemplateStruct& key_template_struct =
      serialization->GetKeyTemplateStruct();
  EXPECT_THAT(key_template_struct.type_url, "type_url");
  EXPECT_THAT(key_template_struct.output_prefix_type,
              OutputPrefixTypeEnum::kTink);
  EXPECT_THAT(key_template_struct.value, test_proto.SerializeAsString());
  TestProto parsed_proto;
  parsed_proto.ParseFromString(key_template_struct.value);
  EXPECT_THAT(parsed_proto.num(), Eq(12345));
}

TEST_F(ProtoParametersSerializationTest,
       CreateFromKeyTemplateWithNonPrintableAsciiTypeURLFails) {
  TestProto test_proto;
  test_proto.set_num(12345);
  KeyTemplate key_template;
  key_template.set_value(test_proto.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  key_template.set_type_url("type_url\x01");
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(key_template);

  EXPECT_THAT(
      serialization.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Non-printable ASCII character in type URL.")));
}

TEST_F(ProtoParametersSerializationTest, CreateFromKeyTemplateStruct) {
  TestProto test_proto;
  test_proto.set_num(12345);
  KeyTemplateStruct key_template_struct;
  key_template_struct.value = test_proto.SerializeAsString();
  key_template_struct.output_prefix_type = OutputPrefixTypeEnum::kTink;
  key_template_struct.type_url = "type_url";
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(key_template_struct);
  ASSERT_THAT(serialization.status(), IsOk());

  const KeyTemplateStruct& key_template = serialization->GetKeyTemplateStruct();
  EXPECT_THAT(key_template.type_url, "type_url");
  EXPECT_THAT(key_template.output_prefix_type, OutputPrefixTypeEnum::kTink);
  EXPECT_THAT(key_template.value, test_proto.SerializeAsString());
  TestProto parsed_proto;
  parsed_proto.ParseFromString(key_template.value);
  EXPECT_THAT(parsed_proto.num(), Eq(12345));
}

TEST_F(ProtoParametersSerializationTest, CreateFromProtoKeyTemplate) {
  TestProto test_proto;
  test_proto.set_num(12345);
  ProtoKeyTemplate key_template_proto;
  key_template_proto.set_value(test_proto.SerializeAsString());
  key_template_proto.set_output_prefix_type(OutputPrefixTypeEnum::kTink);
  key_template_proto.set_type_url("type_url");
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(key_template_proto);
  ASSERT_THAT(serialization.status(), IsOk());

  const KeyTemplateStruct& key_template = serialization->GetKeyTemplateStruct();
  EXPECT_THAT(key_template.type_url, "type_url");
  EXPECT_THAT(key_template.output_prefix_type, OutputPrefixTypeEnum::kTink);
  EXPECT_THAT(key_template.value, test_proto.SerializeAsString());
  TestProto parsed_proto;
  parsed_proto.ParseFromString(key_template.value);
  EXPECT_THAT(parsed_proto.num(), Eq(12345));
}

TEST_F(ProtoParametersSerializationTest,
       CreateFromKeyTemplateStructWithNonPrintableAsciiTypeURLFails) {
  TestProto test_proto;
  test_proto.set_num(12345);
  KeyTemplateStruct key_template_struct;
  key_template_struct.value = test_proto.SerializeAsString();
  key_template_struct.output_prefix_type = OutputPrefixTypeEnum::kTink;
  key_template_struct.type_url = "type_url\x01";
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(key_template_struct);

  EXPECT_THAT(
      serialization.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Non-printable ASCII character in type URL.")));
}

TEST_F(ProtoParametersSerializationTest, GetKeyTemplateStruct) {
  TestProto test_proto;
  test_proto.set_num(12345);
  KeyTemplate key_template;
  key_template.set_value(test_proto.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  key_template.set_type_url("type_url");
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(key_template);
  ASSERT_THAT(serialization.status(), IsOk());

  const KeyTemplateStruct& key_template_struct =
      serialization->GetKeyTemplateStruct();
  EXPECT_THAT(key_template_struct.type_url, "type_url");
  EXPECT_THAT(key_template_struct.output_prefix_type,
              OutputPrefixTypeEnum::kTink);
  EXPECT_THAT(key_template_struct.value, test_proto.SerializeAsString());
  TestProto parsed_proto;
  parsed_proto.ParseFromString(key_template_struct.value);
  EXPECT_THAT(parsed_proto.num(), Eq(12345));
}

TEST_F(ProtoParametersSerializationTest, Equals) {
  TestProto test_proto;
  test_proto.set_num(12345);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create("type_url",
                                           OutputPrefixTypeEnum::kRaw,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<ProtoParametersSerialization> other_serialization =
      ProtoParametersSerialization::Create("type_url",
                                           OutputPrefixTypeEnum::kRaw,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(other_serialization.status(), IsOk());

  EXPECT_THAT(Equals(*serialization, *other_serialization), IsTrue());
}

TEST_F(ProtoParametersSerializationTest, TypeUrlNotEqual) {
  TestProto test_proto;
  test_proto.set_num(12345);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create("type_url",
                                           OutputPrefixTypeEnum::kRaw,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<ProtoParametersSerialization> other_serialization =
      ProtoParametersSerialization::Create("other_url",
                                           OutputPrefixTypeEnum::kRaw,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(other_serialization.status(), IsOk());

  EXPECT_THAT(Equals(*serialization, *other_serialization), IsFalse());
}

TEST_F(ProtoParametersSerializationTest, OutputPrefixTypeNotEqual) {
  TestProto test_proto;
  test_proto.set_num(12345);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create("type_url",
                                           OutputPrefixTypeEnum::kRaw,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<ProtoParametersSerialization> other_serialization =
      ProtoParametersSerialization::Create("type_url",
                                           OutputPrefixTypeEnum::kTink,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(other_serialization.status(), IsOk());

  EXPECT_THAT(Equals(*serialization, *other_serialization), IsFalse());
}

TEST_F(ProtoParametersSerializationTest, DifferentValueNotEqual) {
  TestProto test_proto;
  test_proto.set_num(12345);
  TestProto other_proto;
  other_proto.set_num(67890);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create("type_url",
                                           OutputPrefixTypeEnum::kRaw,
                                           test_proto.SerializeAsString());
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<ProtoParametersSerialization> other_serialization =
      ProtoParametersSerialization::Create("type_url",
                                           OutputPrefixTypeEnum::kRaw,
                                           other_proto.SerializeAsString());
  ASSERT_THAT(other_serialization.status(), IsOk());

  EXPECT_THAT(Equals(*serialization, *other_serialization), IsFalse());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
