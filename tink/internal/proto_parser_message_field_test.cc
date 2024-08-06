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
#include "tink/internal/proto_parser_message_field.h"

#include <cstdint>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/btree_map.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parsing_low_level_parser.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::HexEncode;
using ::crypto::tink::test::IsOk;
using ::testing::Eq;
using ::testing::Not;
using ::testing::Test;

struct InnerStruct {
  uint32_t uint32_member_1;
  uint32_t uint32_member_2;
};

struct OuterStruct {
  InnerStruct inner_member;
};

LowLevelParser<InnerStruct> InnerStructFields() {
  absl::btree_map<int, std::unique_ptr<Field<InnerStruct>>> fields;
  fields.insert({1, std::make_unique<Uint32Field<InnerStruct>>(
                        1, &InnerStruct::uint32_member_1)});
  fields.insert({2, std::make_unique<Uint32Field<InnerStruct>>(
                        2, &InnerStruct::uint32_member_2)});
  return LowLevelParser<InnerStruct>(std::move(fields));
}

TEST(MessageField, ClearMemberWorks) {
  MessageField<OuterStruct, InnerStruct> field(1, &OuterStruct::inner_member,
                                               InnerStructFields());
  OuterStruct s;
  s.inner_member.uint32_member_1 = 123;
  s.inner_member.uint32_member_2 = 456;

  field.ClearMember(s);
  EXPECT_THAT(s.inner_member.uint32_member_1, Eq(0));
  EXPECT_THAT(s.inner_member.uint32_member_2, Eq(0));
}

TEST(MessageField, ConsumeIntoMemberSuccessCases) {
  MessageField<OuterStruct, InnerStruct> field(1, &OuterStruct::inner_member,
                                               InnerStructFields());
  OuterStruct s;
  s.inner_member.uint32_member_1 = 0;
  s.inner_member.uint32_member_2 = 0;

  std::string bytes =
      absl::StrCat(/* 4 bytes */ HexDecodeOrDie("04"),
                   /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
                   /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"));
  absl::string_view bytes_view = bytes;
  EXPECT_THAT(field.ConsumeIntoMember(bytes_view, s), IsOk());
  EXPECT_THAT(s.inner_member.uint32_member_1, Eq(0x23));
  EXPECT_THAT(s.inner_member.uint32_member_2, Eq(0x7a));
}

TEST(MessageField, ConsumeIntoMemberEmptyString) {
  MessageField<OuterStruct, InnerStruct> field(1, &OuterStruct::inner_member,
                                               InnerStructFields());
  OuterStruct s;
  s.inner_member.uint32_member_1 = 0;
  s.inner_member.uint32_member_2 = 0;

  std::string bytes = HexDecodeOrDie("00");
  absl::string_view bytes_view = bytes;
  // This does not clear the fields because if there are multiple blocks
  // for the same field we merge them.
  EXPECT_THAT(field.ConsumeIntoMember(bytes_view, s), IsOk());
  EXPECT_THAT(s.inner_member.uint32_member_1, Eq(0));
  EXPECT_THAT(s.inner_member.uint32_member_2, Eq(0));
}

TEST(MessageField, ConsumeIntoMemberDoesNotClear) {
  MessageField<OuterStruct, InnerStruct> field(1, &OuterStruct::inner_member,
                                               InnerStructFields());
  OuterStruct s;
  s.inner_member.uint32_member_1 = 10;
  s.inner_member.uint32_member_2 = 0;

  std::string bytes =
      absl::StrCat(/* 4 bytes */ HexDecodeOrDie("02"),
                   /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"));
  absl::string_view bytes_view = bytes;
  // This does not clear uint32_member_1 because if there are multiple blocks
  // for the same field we merge them.
  EXPECT_THAT(field.ConsumeIntoMember(bytes_view, s), IsOk());
  EXPECT_THAT(s.inner_member.uint32_member_1, Eq(10));
  EXPECT_THAT(s.inner_member.uint32_member_2, Eq(0x7a));
}

TEST(MessageField, EmptyWithoutVarint) {
  MessageField<OuterStruct, InnerStruct> field(1, &OuterStruct::inner_member,
                                               InnerStructFields());
  OuterStruct s;

  std::string bytes = "";
  absl::string_view bytes_view = bytes;
  EXPECT_THAT(field.ConsumeIntoMember(bytes_view, s), Not(IsOk()));
}

TEST(MessageField, InvalidVarint) {
  MessageField<OuterStruct, InnerStruct> field(1, &OuterStruct::inner_member,
                                               InnerStructFields());
  OuterStruct s;

  std::string bytes = absl::StrCat(HexDecodeOrDie("8000"), "abcde");
  absl::string_view bytes_view = bytes;
  EXPECT_THAT(field.ConsumeIntoMember(bytes_view, s), Not(IsOk()));
}

TEST(MessageField, SerializeEmpty) {
  MessageField<OuterStruct, InnerStruct> field(1, &OuterStruct::inner_member,
                                               InnerStructFields());
  OuterStruct s;
  s.inner_member.uint32_member_1 = 0;
  s.inner_member.uint32_member_2 = 0;

  std::string buffer = "abc";
  absl::Span<char> buffer_span = absl::MakeSpan(buffer);
  EXPECT_THAT(field.GetSerializedSize(s), Eq(1));
  EXPECT_THAT(field.SerializeInto(buffer_span, s), IsOk());
  EXPECT_THAT(buffer_span.size(), Eq(2));
  EXPECT_THAT(HexEncode(buffer.substr(0, 1)), Eq("00"));
}

TEST(MessageField, SerializeNonEmpty) {
  MessageField<OuterStruct, InnerStruct> field(1, &OuterStruct::inner_member,
                                               InnerStructFields());
  OuterStruct s;
  s.inner_member.uint32_member_1 = 0x23;
  s.inner_member.uint32_member_2 = 0x7a;
  std::string buffer = "BUFFERBUFFERBUFFERBUFFER";
  absl::Span<char> buffer_span = absl::MakeSpan(buffer);
  EXPECT_THAT(field.GetSerializedSize(s), Eq(5));
  EXPECT_THAT(field.SerializeInto(buffer_span, s), IsOk());
  EXPECT_THAT(buffer_span.size(), Eq(buffer.size() - 5));
  EXPECT_THAT(&buffer_span[0], Eq(&buffer[5]));
  EXPECT_THAT(HexEncode(buffer.substr(0, 5)),
              Eq(absl::StrCat(/* 4 bytes */ ("04"),
                              /* Int field, tag 1, value 0x23 */ ("0823"),
                              /* Int field, tag 2, value 0x7a */ ("107a"))));
  // Rest is untouched
  EXPECT_THAT(buffer.substr(5), Eq("RBUFFERBUFFERBUFFER"));
}

TEST(MessageField, SerializeTooSmallBuffer) {
  MessageField<OuterStruct, InnerStruct> field(1, &OuterStruct::inner_member,
                                               InnerStructFields());
  OuterStruct s;
  s.inner_member.uint32_member_1 = 0x23;
  s.inner_member.uint32_member_2 = 0x7a;
  std::string buffer = "BUFF";
  absl::Span<char> buffer_span = absl::MakeSpan(buffer);
  EXPECT_THAT(field.SerializeInto(buffer_span, s), Not(IsOk()));
}

// The buffer won't even hold the varint.
TEST(MessageField, SerializeVerySmallBuffer) {
  MessageField<OuterStruct, InnerStruct> field(1, &OuterStruct::inner_member,
                                               InnerStructFields());
  OuterStruct s;
  s.inner_member.uint32_member_1 = 0x23;
  s.inner_member.uint32_member_2 = 0x7a;
  std::string buffer;
  absl::Span<char> buffer_span = absl::MakeSpan(buffer);
  EXPECT_THAT(field.SerializeInto(buffer_span, s), Not(IsOk()));
}

TEST(MessageField, RequiresSerialization) {
  MessageField<OuterStruct, InnerStruct> field(1, &OuterStruct::inner_member,
                                               InnerStructFields());
  OuterStruct s;
  s.inner_member.uint32_member_1 = 0;
  s.inner_member.uint32_member_2 = 0;
  EXPECT_THAT(field.RequiresSerialization(s), Eq(false));
  s.inner_member.uint32_member_1 = 1;
  EXPECT_THAT(field.RequiresSerialization(s), Eq(true));
  s.inner_member.uint32_member_1 = 0;
  s.inner_member.uint32_member_2 = 2;
  EXPECT_THAT(field.RequiresSerialization(s), Eq(true));
}

}  // namespace

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
