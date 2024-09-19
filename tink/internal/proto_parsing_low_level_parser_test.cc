// Copyright 2024 Google LLC
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

#include "tink/internal/proto_parsing_low_level_parser.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/btree_map.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_test_proto.pb.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

struct ParsedStruct {
  uint32_t uint32_member_1;
  std::string string_member_1;
};

absl::btree_map<int, std::unique_ptr<Field<ParsedStruct>>> MakeFields() {
  absl::btree_map<int, std::unique_ptr<Field<ParsedStruct>>> fields;
  fields.insert({1, std::make_unique<Uint32Field<ParsedStruct>>(
                        1, &ParsedStruct::uint32_member_1)});
  fields.insert({3, std::make_unique<BytesField<ParsedStruct, std::string>>(
                        3, &ParsedStruct::string_member_1)});
  return fields;
}

namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::HexEncode;
using ::crypto::tink::test::IsOk;
using ::testing::Eq;
using ::testing::IsEmpty;

TEST(LowLevelParserTest, ClearAllFields) {
  LowLevelParser<ParsedStruct> parser(MakeFields());
  ParsedStruct s;
  s.uint32_member_1 = 123;
  s.string_member_1 = "foo";
  parser.ClearAllFields(s);
  EXPECT_THAT(s.uint32_member_1, Eq(0));
  EXPECT_THAT(s.string_member_1, Eq(""));
}

TEST(LowLevelParserTest, ConsumeIntoFieldsBasic) {
  ProtoTestProto proto;
  proto.set_uint32_field_1(123);
  proto.set_bytes_field_1("foo");

  LowLevelParser<ParsedStruct> parser(MakeFields());
  ParsedStruct s;
  parser.ClearAllFields(s);
  std::string serialized = proto.SerializeAsString();
  ParsingState parsing_state = ParsingState(serialized);
  ASSERT_THAT(parser.ConsumeIntoAllFields(parsing_state, s), IsOk());
  ASSERT_THAT(parsing_state.RemainingData(), IsEmpty());
  EXPECT_THAT(s.uint32_member_1, Eq(123));
  EXPECT_THAT(s.string_member_1, Eq("foo"));
}

TEST(LowLevelParserTest, ConsumeIntoFieldsWrongWiretypeIgnored) {
  LowLevelParser<ParsedStruct> parser(MakeFields());
  ParsedStruct s;
  parser.ClearAllFields(s);
  std::string serialized = HexDecodeOrDie(
      absl::StrCat(/*Wiretype: kVarint, Tag 3*/ "18", /* Varint: 1*/ "08"));
  ParsingState parsing_state = ParsingState(serialized);
  ASSERT_THAT(parser.ConsumeIntoAllFields(parsing_state, s), IsOk());
  ASSERT_THAT(parsing_state.RemainingData(), IsEmpty());
  EXPECT_THAT(s.string_member_1, Eq(""));
}

TEST(LowLevelParserTest, RequiresSerializatoin) {
  LowLevelParser<ParsedStruct> parser(MakeFields());
  ParsedStruct s;
  parser.ClearAllFields(s);
  EXPECT_THAT(parser.RequiresSerialization(s), Eq(false));

  parser.ClearAllFields(s);
  s.uint32_member_1 = 123;
  EXPECT_THAT(parser.RequiresSerialization(s), Eq(true));

  parser.ClearAllFields(s);
  s.string_member_1 = "foo";
  EXPECT_THAT(parser.RequiresSerialization(s), Eq(true));
}

TEST(LowLevelParserTest, GetSerializedSize) {
  LowLevelParser<ParsedStruct> parser(MakeFields());
  ParsedStruct s;
  parser.ClearAllFields(s);
  EXPECT_THAT(parser.GetSerializedSize(s), Eq(0));

  parser.ClearAllFields(s);
  s.uint32_member_1 = 123;
  EXPECT_THAT(parser.GetSerializedSize(s), Eq(2));

  parser.ClearAllFields(s);
  s.string_member_1 = "foo";
  EXPECT_THAT(parser.GetSerializedSize(s), Eq(5));
}

TEST(LowLevelParserTest, SerializeInto) {
  LowLevelParser<ParsedStruct> parser(MakeFields());
  ParsedStruct s;
  parser.ClearAllFields(s);

  std::string serialized;
  serialized.resize(100);
  SerializationState serialized_span =
      SerializationState(absl::MakeSpan(serialized));

  s.uint32_member_1 = 0x7b;
  EXPECT_THAT(parser.SerializeInto(serialized_span, s), IsOk());
  EXPECT_THAT(serialized_span.GetBuffer().size(), Eq(98));
  EXPECT_THAT(HexEncode(serialized.substr(0, 2)), Eq("087b"));
}

TEST(LowLevelParserTest, SerializeIntoMultipleFields) {
  LowLevelParser<ParsedStruct> parser(MakeFields());
  ParsedStruct s;
  parser.ClearAllFields(s);

  std::string serialized;
  serialized.resize(100);
  SerializationState serialized_span =
      SerializationState(absl::MakeSpan(serialized));

  s.uint32_member_1 = 0x7b;
  s.string_member_1 = "AAAAA";
  EXPECT_THAT(parser.SerializeInto(serialized_span, s), IsOk());
  EXPECT_THAT(serialized_span.GetBuffer().size(), Eq(91));
  EXPECT_THAT(HexEncode(serialized.substr(0, 9)), Eq("087b1a054141414141"));
}

TEST(LowLevelParserTest, MoveConstructorWorks) {
  LowLevelParser<ParsedStruct> parser(MakeFields());
  LowLevelParser<ParsedStruct> parser2(std::move(parser));
  ParsedStruct s;
  s.uint32_member_1 = 123;
  parser2.ClearAllFields(s);
  EXPECT_THAT(s.uint32_member_1, Eq(0));
}

TEST(LowLevelParserTest, MoveAssignmentWorks) {
  LowLevelParser<ParsedStruct> parser(MakeFields());
  LowLevelParser<ParsedStruct> parser2(
      (absl::btree_map<int, std::unique_ptr<Field<ParsedStruct>>>()));
  parser2 = std::move(parser);
  ParsedStruct s;
  s.uint32_member_1 = 123;
  parser2.ClearAllFields(s);
  EXPECT_THAT(s.uint32_member_1, Eq(0));
}

TEST(LowLevelParserTest, SkipUnknownField) {
  absl::btree_map<int, std::unique_ptr<Field<ParsedStruct>>> fields;
  fields.insert({1, std::make_unique<Uint32Field<ParsedStruct>>(
                        1, &ParsedStruct::uint32_member_1)});
  fields.insert({3, std::make_unique<BytesField<ParsedStruct, std::string>>(
                        3, &ParsedStruct::string_member_1)});

  ProtoTestProto proto1;
  proto1.set_uint32_field_1(123);
  // Unknown field
  ProtoTestProto proto2;
  proto2.set_uint32_field_2(555);

  ProtoTestProto proto3;
  proto3.set_bytes_field_1("foo");

  LowLevelParser<ParsedStruct> parser(std::move(fields));
  ParsedStruct s;
  parser.ClearAllFields(s);
  // Create a message with all 3 fields, serialized in order 1, 2, 3.
  std::string serialized =
      absl::StrCat(proto1.SerializeAsString(), proto2.SerializeAsString(),
                   proto3.SerializeAsString());
  ParsingState parsing_state = ParsingState(serialized);
  ASSERT_THAT(parser.ConsumeIntoAllFields(parsing_state, s), IsOk());
  ASSERT_THAT(parsing_state.RemainingData(), IsEmpty());
  EXPECT_THAT(s.uint32_member_1, Eq(123));
  EXPECT_THAT(s.string_member_1, Eq("foo"));
}

}  // namespace

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
