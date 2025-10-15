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
#include "tink/internal/proto_parser_message.h"

#include <cstdint>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/testing/field_with_number.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
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
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::Test;

class InnerStruct final : public Message {
 public:
  InnerStruct() : Message(&fields_) {}
  InnerStruct(uint32_t uint32_member_1, uint32_t uint32_member_2)
      : Message(&fields_) {
    uint32_member_1_.set_value(uint32_member_1);
    uint32_member_2_.set_value(uint32_member_2);
  }
  InnerStruct(const InnerStruct& other) : Message(&fields_) {
    uint32_member_1_.set_value(other.uint32_member_1_.value());
    uint32_member_2_.set_value(other.uint32_member_2_.value());
  }

  uint32_t uint32_member_1() const { return uint32_member_1_.value(); }
  void set_uint32_member_1(uint32_t value) {
    uint32_member_1_.set_value(value);
  }
  uint32_t uint32_member_2() const { return uint32_member_2_.value(); }
  void set_uint32_member_2(uint32_t value) {
    uint32_member_2_.set_value(value);
  }

  bool operator==(const InnerStruct& other) const {
    return uint32_member_1_.value() == other.uint32_member_1_.value() &&
           uint32_member_2_.value() == other.uint32_member_2_.value();
  }

 private:
  Uint32OwningField uint32_member_1_{1};
  Uint32OwningField uint32_member_2_{2};

  Fields fields_{&uint32_member_1_, &uint32_member_2_};
};

class OuterStruct : public Message {
 public:
  OuterStruct() : Message(&fields_) {}

  const InnerStruct& inner_member() const { return inner_member_.value(); }
  InnerStruct& inner_member() { return inner_member_.value(); }

  using Message::SerializeAsString;

 private:
  MessageOwningField<InnerStruct> inner_member_{1};
  Fields fields_{&inner_member_};
};

TEST(MessageTest, Clear) {
  OuterStruct s;
  s.inner_member().set_uint32_member_1(123);
  s.inner_member().set_uint32_member_2(456);
  s.Clear();
  EXPECT_THAT(s.inner_member().uint32_member_1(), Eq(0));
  EXPECT_THAT(s.inner_member().uint32_member_2(), Eq(0));
}

TEST(MessageTest, SerializeAsSecretDataSuccess) {
  OuterStruct s;
  s.inner_member().set_uint32_member_1(0x23);
  s.inner_member().set_uint32_member_2(0x7a);
  SecretData buffer = s.SerializeAsSecretData();
  EXPECT_THAT(
      util::SecretDataAsStringView(buffer),
      Eq(FieldWithNumber(1).IsSubMessage({FieldWithNumber(1).IsVarint(0x23),
                                          FieldWithNumber(2).IsVarint(0x7a)})));
}

TEST(MessageTest, SerializeAsStringSuccess) {
  OuterStruct s;
  s.inner_member().set_uint32_member_1(0x23);
  s.inner_member().set_uint32_member_2(0x7a);
  std::string buffer = s.SerializeAsString();
  EXPECT_THAT(
      buffer,
      Eq(FieldWithNumber(1).IsSubMessage({FieldWithNumber(1).IsVarint(0x23),
                                          FieldWithNumber(2).IsVarint(0x7a)})));
}

TEST(MessageTest, ParseFromStringSuccess) {
  std::string bytes =
      absl::StrCat(/* Size and tag */ HexDecodeOrDie("0a04"),
                   /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
                   /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"));
  OuterStruct s;
  s.Clear();
  EXPECT_TRUE(s.ParseFromString(bytes));
  EXPECT_THAT(s.inner_member().uint32_member_1(), Eq(0x23));
  EXPECT_THAT(s.inner_member().uint32_member_2(), Eq(0x7a));
}

TEST(MessageTest, SerializeAndParse) {
  OuterStruct s;
  s.inner_member().set_uint32_member_1(0x23);
  s.inner_member().set_uint32_member_2(0x7a);
  SecretData bytes = s.SerializeAsSecretData();
  s.Clear();
  EXPECT_THAT(s.inner_member().uint32_member_1(), Eq(0));
  EXPECT_THAT(s.inner_member().uint32_member_2(), Eq(0));
  EXPECT_TRUE(s.ParseFromString(util::SecretDataAsStringView(bytes)));
  EXPECT_THAT(s.inner_member().uint32_member_1(), Eq(0x23));
  EXPECT_THAT(s.inner_member().uint32_member_2(), Eq(0x7a));
}

TEST(MessageTest, ParseFromStringFails) {
  std::string bytes =
      absl::StrCat(/* 4 bytes */ HexDecodeOrDie("04"),
                   /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
                   /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"));
  bytes.resize(bytes.size() - 1);  // One byte too short.
  OuterStruct s;
  s.Clear();
  EXPECT_FALSE(s.ParseFromString(bytes));
}

TEST(MessageOwningFieldTest, ClearMemberWorks) {
  MessageOwningField<InnerStruct> field(1);
  field.value().set_uint32_member_1(123);
  field.value().set_uint32_member_2(456);
  field.Clear();
  EXPECT_THAT(field.value().uint32_member_1(), Eq(0));
  EXPECT_THAT(field.value().uint32_member_2(), Eq(0));
}

TEST(MessageOwningFieldTest, ConsumeIntoMemberSuccessCases) {
  MessageOwningField<InnerStruct> field(1);
  std::string bytes =
      absl::StrCat(/* 4 bytes */ HexDecodeOrDie("04"),
                   /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
                   /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"),
                   "remaining_data");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining_data"));
  EXPECT_THAT(field.value().uint32_member_1(), Eq(0x23));
  EXPECT_THAT(field.value().uint32_member_2(), Eq(0x7a));
}

TEST(MessageOwningFieldTest, ConsumeIntoMemberWithCrcSuccessCases) {
  MessageOwningField<InnerStruct> field(1);

  std::string bytes =
      absl::StrCat(/* 4 bytes */ HexDecodeOrDie("04"),
                   /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
                   /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"),
                   "remaining_data");
  absl::crc32c_t crc{};
  ParsingState parsing_state = ParsingState(bytes, &crc);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining_data"));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c(bytes.substr(0, 5))));
  EXPECT_THAT(field.value().uint32_member_1(), Eq(0x23));
  EXPECT_THAT(field.value().uint32_member_2(), Eq(0x7a));
}

TEST(MessageOwningFieldTest, ConsumeIntoMemberEmptyString) {
  MessageOwningField<InnerStruct> field(1);
  field.Clear();

  std::string bytes = HexDecodeOrDie("00");
  ParsingState parsing_state = ParsingState(bytes);
  // This does not clear the fields because if there are multiple blocks
  // for the same field we merge them.
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.value().uint32_member_1(), Eq(0));
  EXPECT_THAT(field.value().uint32_member_2(), Eq(0));
}

TEST(MessageOwningFieldTest, ConsumeIntoMemberDoesNotClear) {
  MessageOwningField<InnerStruct> field(1);
  field.value().set_uint32_member_1(10);
  field.value().set_uint32_member_2(0);
  std::string bytes = absl::StrCat(/* 4 bytes */ HexDecodeOrDie("02"),
                                   /* Int field, tag 2, value 0x7a */
                                   HexDecodeOrDie("107a"));
  ParsingState parsing_state = ParsingState(bytes);
  // This does not clear uint32_member_1 because if there are multiple blocks
  // for the same field we merge them.
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.value().uint32_member_1(), Eq(10));
  EXPECT_THAT(field.value().uint32_member_2(), Eq(0x7a));
}

TEST(MessageOwningFieldTest, ConsumeIntoMemberVarintTooLong) {
  MessageOwningField<InnerStruct> field(1);
  field.Clear();
  std::string bytes = /* LengthDelimetedLength: */ HexDecodeOrDie("01");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(MessageOwningFieldTest, EmptyWithoutVarint) {
  MessageOwningField<InnerStruct> field(1);
  field.Clear();

  std::string bytes = "";
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(MessageOwningFieldTest, InvalidVarint) {
  MessageOwningField<InnerStruct> field(1);
  field.Clear();

  std::string bytes = absl::StrCat(HexDecodeOrDie("808080808000"), "abcde");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(MessageOwningFieldTest, SerializeEmpty) {
  MessageOwningField<InnerStruct> field(1);
  field.Clear();
  std::string buffer = "abc";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(3));
  EXPECT_THAT(buffer, Eq("abc"));
}

TEST(MessageOwningFieldTest, SerializeNonEmpty) {
  MessageOwningField<InnerStruct> field(1);
  field.value().set_uint32_member_1(0x23);
  field.value().set_uint32_member_2(0x7a);
  std::string buffer = "BUFFERBUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(6));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(buffer.size() - 6));
  EXPECT_THAT(&(state.GetBuffer())[0], Eq(&buffer[6]));
  EXPECT_THAT(
      buffer.substr(0, 6),
      Eq(FieldWithNumber(1).IsSubMessage({FieldWithNumber(1).IsVarint(0x23),
                                          FieldWithNumber(2).IsVarint(0x7a)})));
  // Rest is untouched
  EXPECT_THAT(buffer.substr(6), Eq("BUFFERBUFFERBUFFER"));
}

TEST(MessageOwningFieldTest, SerializeTooSmallBuffer) {
  MessageOwningField<InnerStruct> field(1);
  field.value().set_uint32_member_1(0x23);
  field.value().set_uint32_member_2(0x7a);
  std::string buffer = "BUFFE";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

// The buffer can hold the tag, but not the varint of the length.
TEST(MessageOwningFieldTest, SerializeSmallerBuffer) {
  MessageOwningField<InnerStruct> field(1);
  field.value().set_uint32_member_1(0x23);
  field.value().set_uint32_member_2(0x7a);
  std::string buffer = "B";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

// The buffer won't even hold the varint.
TEST(MessageOwningFieldTest, SerializeVerySmallBuffer) {
  MessageOwningField<InnerStruct> field(1);
  field.value().set_uint32_member_1(0x23);
  field.value().set_uint32_member_2(0x7a);
  std::string buffer;
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

// -----------------------------------------------------------------------------
// RepeatedMessageOwningField tests.

TEST(RepeatedMessageOwningField, ConsumeIntoMemberSuccessCases) {
  RepeatedMessageOwningField<InnerStruct> field{1};

  std::string bytes = absl::StrCat(
      /* 4 bytes */ HexDecodeOrDie("04"),
      /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
      /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"),
      /* 2 bytes */ HexDecodeOrDie("02"),
      /* Int field, tag 1, value 0x01 */ HexDecodeOrDie("0801"),
      "remaining_data");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining_data"));
  EXPECT_THAT(field.values(),
              ElementsAre(InnerStruct(0x23, 0x7a), InnerStruct(0x01, 0)));
}

TEST(RepeatedMessageOwningField, ConsumeIntoMemberWithCrcSuccessCases) {
  RepeatedMessageOwningField<InnerStruct> field{1};

  std::string bytes = absl::StrCat(
      /* 4 bytes */ HexDecodeOrDie("04"),
      /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
      /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"),
      /* 2 bytes */ HexDecodeOrDie("02"),
      /* Int field, tag 1, value 0x01 */ HexDecodeOrDie("0801"),
      "remaining_data");
  absl::crc32c_t crc{};
  ParsingState parsing_state = ParsingState(bytes, &crc);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining_data"));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c(bytes.substr(0, 8))));
  EXPECT_THAT(field.values(),
              ElementsAre(InnerStruct(0x23, 0x7a), InnerStruct(0x01, 0)));
}

TEST(RepeatedMessageOwningField, ConsumeIntoMemberEmptyString) {
  RepeatedMessageOwningField<InnerStruct> field{1};
  std::string bytes = HexDecodeOrDie("00");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.values(), ElementsAre(InnerStruct()));
}

TEST(RepeatedMessageOwningField, ConsumeIntoMemberAppends) {
  RepeatedMessageOwningField<InnerStruct> field{1};
  field.values().push_back(InnerStruct(123, 456));
  std::string bytes = absl::StrCat(
      /* 4 bytes */ HexDecodeOrDie("04"),
      /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
      /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"),
      "remaining_data");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining_data"));
  EXPECT_THAT(field.values(),
              ElementsAre(InnerStruct(123, 456), InnerStruct(0x23, 0x7a)));
}

TEST(RepeatedMessageOwningField, ConsumeIntoMemberVarintTooLong) {
  RepeatedMessageOwningField<InnerStruct> field{1};
  std::string bytes = /* LengthDelimetedLength: */ HexDecodeOrDie("01");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(RepeatedMessageOwningField, EmptyWithoutVarint) {
  RepeatedMessageOwningField<InnerStruct> field{1};
  std::string bytes = "";
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(RepeatedMessageOwningField, InvalidVarint) {
  RepeatedMessageOwningField<InnerStruct> field{1};
  std::string bytes = absl::StrCat(HexDecodeOrDie("808080808000"), "abcde");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(RepeatedMessageOwningField, SerializeEmpty) {
  RepeatedMessageOwningField<InnerStruct> field{1};
  std::string buffer = "abc";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(3));
  EXPECT_THAT(buffer, Eq("abc"));
}

TEST(RepeatedMessageOwningField, SerializeNonEmpty) {
  RepeatedMessageOwningField<InnerStruct> field{1};
  field.values().push_back(InnerStruct(0x23, 0x7a));
  field.values().push_back(InnerStruct());
  field.values().back().set_uint32_member_1((0x01));
  std::string buffer = "BUFFERBUFFERBUFFERBUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(10));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
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

TEST(RepeatedMessageOwningField, SerializeNonEmptyWithEmptyInnerStruct) {
  RepeatedMessageOwningField<InnerStruct> field{1};
  field.values().push_back(InnerStruct());
  std::string buffer = "BUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  // Tag (1 << 3 | 2) = 0x0a, Length = 0x00. Total 2 bytes.
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(2));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(buffer.size() - 2));
  EXPECT_THAT(&(state.GetBuffer())[0], Eq(&buffer[2]));
  EXPECT_THAT(buffer.substr(0, 2), Eq(HexDecodeOrDie("0a00")));
  // Rest is untouched
  EXPECT_THAT(buffer.substr(2), Eq("FFER"));
}

TEST(RepeatedMessageOwningField, SerializeTooSmallBuffer) {
  RepeatedMessageOwningField<InnerStruct> field{1};
  field.values().push_back(InnerStruct(0x23, 0x7a));
  std::string buffer = "BUFFE";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

TEST(RepeatedMessageOwningField, SerializeSmallerBuffer) {
  RepeatedMessageOwningField<InnerStruct> field{1};
  field.values().push_back(InnerStruct(0x23, 0x7a));
  std::string buffer = "B";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

TEST(RepeatedMessageOwningField, SerializeVerySmallBuffer) {
  RepeatedMessageOwningField<InnerStruct> field{1};
  field.values().push_back(InnerStruct(0x23, 0x7a));
  std::string buffer;
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

}  // namespace
}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
