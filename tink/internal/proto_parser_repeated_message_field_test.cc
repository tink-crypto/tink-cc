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
#include "tink/internal/proto_parser_repeated_message_field.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/btree_map.h"
#include "absl/crc/crc32c.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_low_level_parser.h"
#include "tink/internal/testing/field_with_number.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

namespace {

using ::crypto::tink::internal::proto_testing::FieldWithNumber;
using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::Test;

struct InnerStruct {
  uint32_t uint32_member_1 = 0;
  uint32_t uint32_member_2 = 0;
};

struct OuterStruct {
  std::vector<InnerStruct> inner_members;
};

LowLevelParser<InnerStruct> InnerStructFields() {
  absl::btree_map<int, std::unique_ptr<Field<InnerStruct>>> fields;
  fields.insert({1, std::make_unique<Uint32Field<InnerStruct>>(
                        1, &InnerStruct::uint32_member_1)});
  fields.insert({2, std::make_unique<Uint32Field<InnerStruct>>(
                        2, &InnerStruct::uint32_member_2)});
  return LowLevelParser<InnerStruct>(std::move(fields));
}

TEST(RepeatedMessageField, ClearMemberWorks) {
  RepeatedMessageField<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_members, InnerStructFields());
  OuterStruct s;
  s.inner_members.push_back(InnerStruct());
  s.inner_members.back().uint32_member_1 = 123;
  s.inner_members.back().uint32_member_2 = 456;

  field.ClearMember(s);
  EXPECT_THAT(s.inner_members.empty(), IsTrue());
}

TEST(RepeatedMessageField, ConsumeIntoMemberSuccessCases) {
  RepeatedMessageField<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_members, InnerStructFields());
  OuterStruct s;

  std::string bytes = absl::StrCat(
      /* 4 bytes */ HexDecodeOrDie("04"),
      /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
      /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"),
      /* 2 bytes */ HexDecodeOrDie("02"),
      /* Int field, tag 1, value 0x01 */ HexDecodeOrDie("0801"),
      "remaining_data");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining_data"));
  EXPECT_THAT(s.inner_members.size(), Eq(2));
  EXPECT_THAT(s.inner_members[0].uint32_member_1, Eq(0x23));
  EXPECT_THAT(s.inner_members[0].uint32_member_2, Eq(0x7a));
  EXPECT_THAT(s.inner_members[1].uint32_member_1, Eq(0x01));
  EXPECT_THAT(s.inner_members[1].uint32_member_2, Eq(0));
}

TEST(RepeatedMessageField, ConsumeIntoMemberWithCrcSuccessCases) {
  RepeatedMessageField<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_members, InnerStructFields());
  OuterStruct s;

  std::string bytes = absl::StrCat(
      /* 4 bytes */ HexDecodeOrDie("04"),
      /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
      /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"),
      /* 2 bytes */ HexDecodeOrDie("02"),
      /* Int field, tag 1, value 0x01 */ HexDecodeOrDie("0801"),
      "remaining_data");
  absl::crc32c_t crc{};
  ParsingState parsing_state = ParsingState(bytes, &crc);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining_data"));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c(bytes.substr(0, 8))));
  EXPECT_THAT(s.inner_members.size(), Eq(2));
  EXPECT_THAT(s.inner_members[0].uint32_member_1, Eq(0x23));
  EXPECT_THAT(s.inner_members[0].uint32_member_2, Eq(0x7a));
  EXPECT_THAT(s.inner_members[1].uint32_member_1, Eq(0x01));
  EXPECT_THAT(s.inner_members[1].uint32_member_2, Eq(0));
}

TEST(RepeatedMessageField, ConsumeIntoMemberEmptyString) {
  RepeatedMessageField<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_members, InnerStructFields());
  OuterStruct s;

  std::string bytes = HexDecodeOrDie("00");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
  EXPECT_THAT(s.inner_members.size(), Eq(1));
  EXPECT_THAT(s.inner_members[0].uint32_member_1, Eq(0));
  EXPECT_THAT(s.inner_members[0].uint32_member_2, Eq(0));
}

TEST(RepeatedMessageField, ConsumeIntoMemberAppends) {
  RepeatedMessageField<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_members, InnerStructFields());
  OuterStruct s;
  s.inner_members.push_back(InnerStruct());
  s.inner_members.back().uint32_member_1 = 123;
  s.inner_members.back().uint32_member_2 = 456;

  std::string bytes = absl::StrCat(
      /* 4 bytes */ HexDecodeOrDie("04"),
      /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
      /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"),
      "remaining_data");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining_data"));
  EXPECT_THAT(s.inner_members.size(), Eq(2));
  EXPECT_THAT(s.inner_members[0].uint32_member_1, Eq(123));
  EXPECT_THAT(s.inner_members[0].uint32_member_2, Eq(456));
  EXPECT_THAT(s.inner_members[1].uint32_member_1, Eq(0x23));
  EXPECT_THAT(s.inner_members[1].uint32_member_2, Eq(0x7a));
}

TEST(RepeatedMessageField, ConsumeIntoMemberVarintTooLong) {
  RepeatedMessageField<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_members, InnerStructFields());
  OuterStruct s;

  std::string bytes = /* LengthDelimetedLength: */ HexDecodeOrDie("01");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsFalse());
}

TEST(RepeatedMessageField, EmptyWithoutVarint) {
  RepeatedMessageField<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_members, InnerStructFields());
  OuterStruct s;

  std::string bytes = "";
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsFalse());
}

TEST(RepeatedMessageField, InvalidVarint) {
  RepeatedMessageField<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_members, InnerStructFields());
  OuterStruct s;

  std::string bytes = absl::StrCat(HexDecodeOrDie("808080808000"), "abcde");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsFalse());
}

TEST(RepeatedMessageField, SerializeEmpty) {
  RepeatedMessageField<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_members, InnerStructFields());
  OuterStruct s;

  std::string buffer = "abc";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(s), Eq(0));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(3));
  EXPECT_THAT(buffer, Eq("abc"));
}

TEST(RepeatedMessageField, SerializeNonEmpty) {
  RepeatedMessageField<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_members, InnerStructFields());
  OuterStruct s;
  s.inner_members.push_back(InnerStruct());
  s.inner_members.back().uint32_member_1 = 0x23;
  s.inner_members.back().uint32_member_2 = 0x7a;
  s.inner_members.push_back(InnerStruct());
  s.inner_members.back().uint32_member_1 = 0x01;
  std::string buffer = "BUFFERBUFFERBUFFERBUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(s), Eq(10));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(buffer.size() - 10));
  EXPECT_THAT(&(state.GetBuffer())[0], Eq(&buffer[10]));
  EXPECT_THAT(buffer.substr(0, 10),
              Eq(absl::StrCat(FieldWithNumber(1).IsSubMessage(
                                  {FieldWithNumber(1).IsVarint(0x23),
                                   FieldWithNumber(2).IsVarint(0x7a)}),
                              FieldWithNumber(1).IsSubMessage(
                                  {FieldWithNumber(1).IsVarint(0x01)}))));
  // Rest is untouched
  EXPECT_THAT(buffer.substr(10), Eq("ERBUFFERBUFFERBUFFERBUFFER"));
}

TEST(RepeatedMessageField, SerializeNonEmptyWithEmptyInnerStruct) {
  RepeatedMessageField<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_members, InnerStructFields());
  OuterStruct s;
  s.inner_members.push_back(InnerStruct());

  std::string buffer = "BUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  // Tag (1 << 3 | 2) = 0x0a, Length = 0x00. Total 2 bytes.
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(s), Eq(2));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(buffer.size() - 2));
  EXPECT_THAT(&(state.GetBuffer())[0], Eq(&buffer[2]));
  EXPECT_THAT(buffer.substr(0, 2), Eq(HexDecodeOrDie("0a00")));
  // Rest is untouched
  EXPECT_THAT(buffer.substr(2), Eq("FFER"));
}

TEST(RepeatedMessageField, SerializeTooSmallBuffer) {
  RepeatedMessageField<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_members, InnerStructFields());
  OuterStruct s;
  s.inner_members.push_back(InnerStruct());
  s.inner_members.back().uint32_member_1 = 0x23;
  s.inner_members.back().uint32_member_2 = 0x7a;
  std::string buffer = "BUFFE";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), Not(IsOk()));
}

TEST(RepeatedMessageField, SerializeSmallerBuffer) {
  RepeatedMessageField<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_members, InnerStructFields());
  OuterStruct s;
  s.inner_members.push_back(InnerStruct());
  s.inner_members.back().uint32_member_1 = 0x23;
  s.inner_members.back().uint32_member_2 = 0x7a;
  std::string buffer = "B";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), Not(IsOk()));
}

TEST(RepeatedMessageField, SerializeVerySmallBuffer) {
  RepeatedMessageField<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_members, InnerStructFields());
  OuterStruct s;
  s.inner_members.push_back(InnerStruct());
  s.inner_members.back().uint32_member_1 = 0x23;
  s.inner_members.back().uint32_member_2 = 0x7a;
  std::string buffer;
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), Not(IsOk()));
}

}  // namespace

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
