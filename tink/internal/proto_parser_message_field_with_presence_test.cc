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
#include "tink/internal/proto_parser_message_field_with_presence.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/btree_map.h"
#include "absl/crc/crc32c.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
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
  uint32_t uint32_member_1;
  uint32_t uint32_member_2;
};

struct OuterStruct {
  absl::optional<InnerStruct> inner_member;
};

LowLevelParser<InnerStruct> InnerStructFields() {
  absl::btree_map<int, std::unique_ptr<Field<InnerStruct>>> fields;
  fields.insert({1, std::make_unique<Uint32Field<InnerStruct>>(
                        1, &InnerStruct::uint32_member_1)});
  fields.insert({2, std::make_unique<Uint32Field<InnerStruct>>(
                        2, &InnerStruct::uint32_member_2)});
  return LowLevelParser<InnerStruct>(std::move(fields));
}

TEST(MessageFieldWithPresenceTest, ClearMemberWorks) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;
  s.inner_member = {123, 456};

  field.ClearMember(s);
  EXPECT_THAT(s.inner_member.has_value(), IsFalse());
}

TEST(MessageFieldWithPresenceTest, ConsumeIntoMemberSuccessCases) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;
  s.inner_member = {0, 0};

  std::string bytes =
      absl::StrCat(/* 4 bytes */ HexDecodeOrDie("04"),
                   /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
                   /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"),
                   "remaining_data");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining_data"));
  ASSERT_THAT(s.inner_member.has_value(), IsTrue());
  EXPECT_THAT(s.inner_member->uint32_member_1, Eq(0x23));
  EXPECT_THAT(s.inner_member->uint32_member_2, Eq(0x7a));
}

TEST(MessageFieldWithPresenceTest, ConsumeIntoMemberWithCrcSuccessCases) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;

  std::string bytes =
      absl::StrCat(/* 4 bytes */ HexDecodeOrDie("04"),
                   /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
                   /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"),
                   "remaining_data");
  absl::crc32c_t crc{};
  ParsingState parsing_state = ParsingState(bytes, &crc);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining_data"));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c(bytes.substr(0, 5))));
  EXPECT_THAT(s.inner_member->uint32_member_1, Eq(0x23));
  EXPECT_THAT(s.inner_member->uint32_member_2, Eq(0x7a));
}

TEST(MessageFieldWithPresenceTest, ConsumeIntoMemberEmptyStringNullopt) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;

  std::string bytes = HexDecodeOrDie("00");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
  ASSERT_THAT(s.inner_member.has_value(), IsTrue());
  EXPECT_THAT(s.inner_member->uint32_member_1, Eq(0));
  EXPECT_THAT(s.inner_member->uint32_member_2, Eq(0));
}

TEST(MessageFieldWithPresenceTest, ConsumeIntoMemberEmptyString) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;
  s.inner_member = {10, 0};

  std::string bytes = HexDecodeOrDie("00");
  ParsingState parsing_state = ParsingState(bytes);
  // This does not clear the fields because if there are multiple blocks
  // for the same field we merge them.
  ASSERT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
  ASSERT_THAT(s.inner_member.has_value(), IsTrue());
  EXPECT_THAT(s.inner_member->uint32_member_1, Eq(10));
  EXPECT_THAT(s.inner_member->uint32_member_2, Eq(0));
}

TEST(MessageFieldWithPresenceTest, ConsumeIntoMemberDoesNotClear) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;
  s.inner_member = {10, 0};

  std::string bytes =
      absl::StrCat(/* 4 bytes */ HexDecodeOrDie("02"),
                   /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"));
  ParsingState parsing_state = ParsingState(bytes);
  // This does not clear uint32_member_1 because if there are multiple blocks
  // for the same field we merge them.
  ASSERT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
  EXPECT_THAT(s.inner_member.has_value(), IsTrue());
  EXPECT_THAT(s.inner_member->uint32_member_1, Eq(10));
  EXPECT_THAT(s.inner_member->uint32_member_2, Eq(0x7a));
}

TEST(MessageFieldWithPresenceTest, ConsumeIntoMemberWithInnerStructNullopt) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;

  std::string bytes =
      absl::StrCat(/* 4 bytes */ HexDecodeOrDie("02"),
                   /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"));
  ParsingState parsing_state = ParsingState(bytes);
  // This does not clear uint32_member_1 because if there are multiple blocks
  // for the same field we merge them.
  ASSERT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
  EXPECT_THAT(s.inner_member.has_value(), IsTrue());
  EXPECT_THAT(s.inner_member->uint32_member_1, Eq(0));  // Default value.
  EXPECT_THAT(s.inner_member->uint32_member_2, Eq(0x7a));
}

TEST(MessageFieldWithPresenceTest, ConsumeIntoMemberVarintTooLong) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;

  std::string bytes = /* LengthDelimetedLength: */ HexDecodeOrDie("01");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsFalse());
}

TEST(MessageFieldWithPresenceTest, EmptyWithoutVarint) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;

  std::string bytes = "";
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsFalse());
}

TEST(MessageFieldWithPresenceTest, InvalidVarint) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;

  std::string bytes = absl::StrCat(HexDecodeOrDie("808080808000"), "abcde");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsFalse());
}

// When the optional struct is not set, we produce an empty serialization.
TEST(MessageFieldWithPresenceTest, SerializeNulloptProducesEmptySerialization) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;

  std::string buffer = "abc";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(s), Eq(0));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(3));
  EXPECT_THAT(buffer, Eq("abc"));
}

// When the optional struct is set to the default value, we produce a
// serialization of the empty submessage.
TEST(MessageFieldWithPresenceTest,
     SerializeInnerStructWithDefaultValuesProducesEmptySubmessage) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;
  s.inner_member = InnerStruct{};

  std::string buffer = "abc";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(s), Eq(2));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(1));
  // Serialized as empty submessage.
  EXPECT_THAT(buffer.substr(0, 2), Eq(FieldWithNumber(1).IsSubMessage({})));
}

TEST(MessageFieldWithPresenceTest, SerializeNonEmpty) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;
  s.inner_member = {0x23, 0x7a};
  std::string buffer = "BUFFERBUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(s), Eq(6));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(buffer.size() - 6));
  EXPECT_THAT(&(state.GetBuffer())[0], Eq(&buffer[6]));
  EXPECT_THAT(
      buffer.substr(0, 6),
      Eq(FieldWithNumber(1).IsSubMessage({FieldWithNumber(1).IsVarint(0x23),
                                          FieldWithNumber(2).IsVarint(0x7a)})));
  // Rest is untouched
  EXPECT_THAT(buffer.substr(6), Eq("BUFFERBUFFERBUFFER"));
}

TEST(MessageFieldWithPresenceTest, SerializeTooSmallBuffer) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;
  s.inner_member = {0x23, 0x7a};
  std::string buffer = "BUFFE";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), Not(IsOk()));
}

// The buffer can hold the tag, but not the varint of the length.
TEST(MessageFieldWithPresenceTest, SerializeSmallerBuffer) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;
  s.inner_member = {0x23, 0x7a};
  std::string buffer = "B";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), Not(IsOk()));
}

// The buffer won't even hold the varint.
TEST(MessageFieldWithPresenceTest, SerializeVerySmallBuffer) {
  MessageFieldWithPresence<OuterStruct, InnerStruct> field(
      1, &OuterStruct::inner_member, InnerStructFields());
  OuterStruct s;
  s.inner_member = {0x23, 0x7a};
  std::string buffer;
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), Not(IsOk()));
}

}  // namespace

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
