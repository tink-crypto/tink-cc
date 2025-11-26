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

#include "tink/internal/proto_parser_enum_field.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
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
using ::testing::IsEmpty;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;

enum class MyEnum : uint32_t {
  k0 = 0,
  k1 = 1,
};

bool AlwaysValid(uint32_t v) { return true; }
bool IsZeroOrOne(uint32_t v) { return v == 0 || v == 1; }

std::vector<std::pair<std::string, uint32_t>> GetUint32TestCases() {
  return std::vector<std::pair<std::string, uint32_t>>{
      {"01", 1}, {"7f", 127}, {"8001", 128}, {"a274", 14882}};
}

TEST(EnumField, ClearkExplicit) {
  EnumField<MyEnum> field(1, &AlwaysValid);
  EXPECT_THAT(field.has_value(), IsFalse());
  EXPECT_THAT(field.value(), Eq(MyEnum::k0));
  field.set_value(MyEnum::k1);
  EXPECT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value(), Eq(MyEnum::k1));
  field.Clear();
  EXPECT_THAT(field.has_value(), IsFalse());
  EXPECT_THAT(field.value(), Eq(MyEnum::k0));
  field.set_value(MyEnum::k0);
  EXPECT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value(), Eq(MyEnum::k0));
}

TEST(EnumFieldDeathTest, CreateWithNonDefaultEnumValueAndkImplicit) {
  EXPECT_DEATH(EnumField<MyEnum> field(1, &AlwaysValid, MyEnum::k1,
                                       ProtoFieldOptions::kImplicit),
               "Default value must be 0 if options are kImplicit.");
}

TEST(EnumField, ClearkImplicit) {
  EnumField<MyEnum> field(1, &AlwaysValid, MyEnum::k0,
                          ProtoFieldOptions::kImplicit);
  EXPECT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value(), Eq(MyEnum::k0));
  field.set_value(MyEnum::k1);
  EXPECT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value(), Eq(MyEnum::k1));
  field.Clear();
  EXPECT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value(), Eq(MyEnum::k0));
  field.set_value(MyEnum::k0);
  EXPECT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value(), Eq(MyEnum::k0));
}

TEST(EnumField, ClearkAlwaysPresent) {
  EnumField<MyEnum> field(1, &AlwaysValid, MyEnum::k0,
                          ProtoFieldOptions::kAlwaysPresent);
  EXPECT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value(), Eq(MyEnum::k0));
  field.set_value(MyEnum::k1);
  EXPECT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value(), Eq(MyEnum::k1));
  field.Clear();
  EXPECT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value(), Eq(MyEnum::k0));
  field.set_value(MyEnum::k0);
  EXPECT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value(), Eq(MyEnum::k0));
}

TEST(EnumField, CleaOtherDefaultWorkskNone) {
  EnumField<MyEnum> field(1, &AlwaysValid, MyEnum::k1);
  field.set_value(MyEnum::k0);
  field.Clear();
  EXPECT_THAT(field.value(), Eq(MyEnum::k1));
}

TEST(EnumField, CleaOtherDefaultWorkskAlwaysPresent) {
  EnumField<MyEnum> field(1, &AlwaysValid, MyEnum::k1,
                          ProtoFieldOptions::kAlwaysPresent);
  field.set_value(MyEnum::k0);
  field.Clear();
  EXPECT_THAT(field.value(), Eq(MyEnum::k1));
}

TEST(EnumField, ConsumeIntoMemberSuccessCases) {
  EnumField<MyEnum> field(1, &AlwaysValid);

  for (std::pair<std::string, uint32_t> test_case : GetUint32TestCases()) {
    SCOPED_TRACE(test_case.first);
    std::string serialized = HexDecodeOrDie(test_case.first);
    ParsingState parsing_state = ParsingState(serialized);
    EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
    EXPECT_THAT(field.value(), Eq(static_cast<MyEnum>(test_case.second)));
    EXPECT_THAT(parsing_state.RemainingData(), IsEmpty());
  }
}

TEST(EnumField, ConsumeIntoMemberLeavesRemainingData) {
  EnumField<MyEnum> field(1, &AlwaysValid);
  field.set_value(static_cast<MyEnum>(999));
  std::string serialized =
      absl::StrCat(HexDecodeOrDie("8001"), "remaining data");
  ParsingState parsing_state = ParsingState(serialized);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.value(), Eq(static_cast<MyEnum>(128)));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining data"));
}

TEST(EnumField, ConsumeIntoMemberFailureCases) {
  EnumField<MyEnum> field(1, &AlwaysValid);

  for (std::string test_case :
       {"", /* 11 bytes, too long */ "ffffffffffffffffffff01"}) {
    SCOPED_TRACE(test_case);
    std::string serialized = HexDecodeOrDie(test_case);
    ParsingState parsing_state = ParsingState(serialized);
    EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
  }
}

TEST(EnumField, ConsumeIntoMemberInvalidIgnores) {
  EnumField<MyEnum> field(1, &IsZeroOrOne);
  field.set_value(MyEnum::k1);
  std::string serialized = HexDecodeOrDie(/* 2 as varint */ "02");
  ParsingState parsing_state = ParsingState(serialized);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.value(), Eq(MyEnum::k1));
}

TEST(EnumField, SerializeVarintSuccessCases) {
  EnumField<MyEnum> field(1, &AlwaysValid);

  for (std::pair<std::string, uint32_t> test_case : GetUint32TestCases()) {
    SCOPED_TRACE(test_case.first);
    std::string expected_serialization =
        HexDecodeOrDie(absl::StrCat("08", test_case.first));
    field.set_value(static_cast<MyEnum>(test_case.second));
    ASSERT_THAT(field.GetSerializedSizeIncludingTag(),
                Eq(expected_serialization.size()));

    std::string buffer;
    buffer.resize(expected_serialization.size());
    SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(buffer_span), IsOk());
    EXPECT_THAT(buffer, Eq(expected_serialization));
    EXPECT_THAT(buffer_span.GetBuffer().size(), Eq(0));
  }
}

TEST(EnumField, SerializeEmptykExplicit) {
  {
    EnumField<MyEnum> field(1, &AlwaysValid);
    ASSERT_THAT(field.has_value(), IsFalse());
    EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
    std::string buffer = "abcdef";
    SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(buffer_span), IsOk());
    std::string expected = "abcdef";
    EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
  }
  {
    EnumField<MyEnum> field(1, &AlwaysValid);
    // When set, always serializes.
    field.set_value(MyEnum::k0);
    ASSERT_THAT(field.has_value(), IsTrue());
    EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(2));
    std::string buffer = "abcdef";
    SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(buffer_span), IsOk());
    std::string expected = "cdef";
    EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
  }
}

TEST(EnumField, SerializeEmptykImplicit) {
  {
    EnumField<MyEnum> field(1, &AlwaysValid, {}, ProtoFieldOptions::kImplicit);
    ASSERT_THAT(field.has_value(), IsTrue());
    EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
    std::string buffer = "abcdef";
    SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(buffer_span), IsOk());
    std::string expected = "abcdef";
    EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
  }
  {
    EnumField<MyEnum> field(1, &AlwaysValid, {}, ProtoFieldOptions::kImplicit);
    // Even when set, does not serialize.
    field.set_value(MyEnum::k0);
    ASSERT_THAT(field.has_value(), IsTrue());
    EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
    std::string buffer = "abcdef";
    SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(buffer_span), IsOk());
    std::string expected = "abcdef";
    EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
  }
}

TEST(EnumField, SerializeEmptykAlwaysPresent) {
  EnumField<MyEnum> field(1, &AlwaysValid, MyEnum::k0,
                          ProtoFieldOptions::kAlwaysPresent);
  ASSERT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(2));
  std::string buffer = "abcdef";
  SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(2));
  EXPECT_THAT(field.SerializeWithTagInto(buffer_span), IsOk());
  std::string expected = "cdef";
  EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
}

TEST(EnumField, SerializeEmptyDifferentDefaultkExplicit) {
  EnumField<MyEnum> field(1, &AlwaysValid, MyEnum::k1,
                          ProtoFieldOptions::kExplicit);
  std::string buffer = "abcdef";
  SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
  field.set_value(MyEnum::k1);
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(2));
  EXPECT_THAT(field.SerializeWithTagInto(buffer_span), IsOk());
  std::string expected = "cdef";
  EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
}

TEST(EnumField, SerializeEmptyAlwaysSerialize) {
  EnumField<MyEnum> field(1, &AlwaysValid, MyEnum::k0,
                          ProtoFieldOptions::kAlwaysPresent);
  std::string buffer = "abcdef";
  SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
  field.set_value(MyEnum::k0);

  ASSERT_THAT(field.GetSerializedSizeIncludingTag(), Eq(2));
  EXPECT_THAT(field.SerializeWithTagInto(buffer_span), IsOk());
  std::string expected = "cdef";
  // Note: absl::MakeSpan("cdef").size() == 5 (will add null terminator).
  EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
  EXPECT_THAT(HexEncode(buffer.substr(0, 2)), Eq("0800"));
}

TEST(EnumField, SerializeEmptyAlwaysSerializeDifferentDefault) {
  EnumField<MyEnum> field(1, &AlwaysValid, MyEnum::k1,
                          ProtoFieldOptions::kAlwaysPresent);
  std::string buffer = "abcdef";
  SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
  field.set_value(MyEnum::k1);

  ASSERT_THAT(field.GetSerializedSizeIncludingTag(), Eq(2));
  EXPECT_THAT(field.SerializeWithTagInto(buffer_span), IsOk());
  std::string expected = "cdef";
  // Note: absl::MakeSpan("cdef").size() == 5 (will add null terminator).
  EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
  EXPECT_THAT(HexEncode(buffer.substr(0, 2)), Eq("0801"));
}

TEST(EnumField, SerializeVarintBufferTooSmall) {
  EnumField<MyEnum> field(1, &AlwaysValid);
  for (std::pair<std::string, uint32_t> test_case : GetUint32TestCases()) {
    SCOPED_TRACE(test_case.first);
    field.set_value(static_cast<MyEnum>(test_case.second));
    ASSERT_THAT(field.GetSerializedSizeIncludingTag(),
                Eq(test_case.first.size() / 2 + 1));

    std::string buffer;
    buffer.resize(test_case.first.size() / 2);
    SerializationState state = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
  }
}

TEST(EnumField, SerializeVarintLeavesRemainingData) {
  EnumField<MyEnum> field(1, &AlwaysValid);
  std::string buffer = "abcdef";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  field.set_value(static_cast<MyEnum>(14882));
  // Will overwrite the first two bytes with 0xa274
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(HexEncode(buffer), Eq("08a274646566"));
  std::string expected = "def";
  // Note: absl::MakeSpan("def").size() == 4 (will add null terminator).
  EXPECT_THAT(state.GetBuffer(), Eq(absl::MakeSpan(expected)));
}

TEST(EnumField, FieldNumberAndWireType) {
  EnumField<MyEnum> field(1, &AlwaysValid);
  EXPECT_THAT(field.FieldNumber(), Eq(1));
  EXPECT_THAT(field.GetWireType(), Eq(WireType::kVarint));
  EnumField<MyEnum> field2(2, &IsZeroOrOne);
  EXPECT_THAT(field2.FieldNumber(), Eq(2));
  EXPECT_THAT(field2.GetWireType(), Eq(WireType::kVarint));
}

TEST(EnumField, DefaultValueInitialization) {
  EnumField<MyEnum> field1(1, &IsZeroOrOne, MyEnum::k1);
  EXPECT_THAT(field1.value(), Eq(MyEnum::k1));
}

TEST(EnumField, CopyAndMove) {
  EnumField<MyEnum> field1(1, &IsZeroOrOne, MyEnum::k1);
  field1.set_value(MyEnum::k0);

  // Test copy constructor
  EnumField<MyEnum> field_copy(field1);
  std::string serialized = HexDecodeOrDie(/* 1 as varint */ "01");
  ParsingState parsing_state = ParsingState(serialized);
  EXPECT_THAT(field_copy.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field_copy.value(), Eq(MyEnum::k1));
  EXPECT_THAT(parsing_state.RemainingData(), IsEmpty());

  // Test copy assignment
  field1.set_value(MyEnum::k0);
  EnumField<MyEnum> field_assign(2, &AlwaysValid, MyEnum::k0);
  field_assign = field1;
  serialized = HexDecodeOrDie(/* 1 as varint */ "01");
  parsing_state = ParsingState(serialized);
  EXPECT_THAT(field_assign.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field_assign.value(), Eq(MyEnum::k1));
  EXPECT_THAT(parsing_state.RemainingData(), IsEmpty());

  // Test move constructor
  field1.set_value(MyEnum::k0);
  EnumField<MyEnum> field_move(std::move(field1));
  serialized = HexDecodeOrDie(/* 1 as varint */ "01");
  parsing_state = ParsingState(serialized);
  EXPECT_THAT(field_move.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field_move.value(), Eq(MyEnum::k1));
  EXPECT_THAT(parsing_state.RemainingData(), IsEmpty());

  // Test move assignment
  field_copy.set_value(MyEnum::k0);
  EnumField<MyEnum> field_move_assign(2, &AlwaysValid, MyEnum::k0);
  field_move_assign = std::move(field_copy);
  serialized = HexDecodeOrDie(/* 1 as varint */ "01");
  parsing_state = ParsingState(serialized);
  EXPECT_THAT(field_move_assign.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field_move_assign.value(), Eq(MyEnum::k1));
  EXPECT_THAT(parsing_state.RemainingData(), IsEmpty());
}

}  // namespace
}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
