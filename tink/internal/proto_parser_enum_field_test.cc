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
using ::testing::Not;

enum class MyEnum : uint32_t {
  k0 = 0,
  k1 = 1,
};

bool AlwaysValid(uint32_t v) { return true; }
bool IsZeroOrOne(uint32_t v) { return v == 0 || v == 1; }

struct ExampleStruct {
  MyEnum enum_field;
};

TEST(EnumField, ClearMemberWorks) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  ExampleStruct s;
  s.enum_field = MyEnum::k1;
  field.ClearMember(s);
  EXPECT_THAT(s.enum_field, Eq(MyEnum::k0));
}

std::vector<std::pair<std::string, uint32_t>> GetUint32TestCases() {
  return std::vector<std::pair<std::string, uint32_t>>{
      {"01", 1}, {"7f", 127}, {"8001", 128}, {"a274", 14882}};
}

TEST(EnumField, ConsumeIntoMemberSuccessCases) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  ExampleStruct s;

  for (std::pair<std::string, uint32_t> test_case : GetUint32TestCases()) {
    SCOPED_TRACE(test_case.first);
    std::string serialized = HexDecodeOrDie(test_case.first);
    ParsingState parsing_state = ParsingState(serialized);
    EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsOk());
    EXPECT_THAT(s.enum_field, Eq(static_cast<MyEnum>(test_case.second)));
    EXPECT_THAT(parsing_state.RemainingData(), IsEmpty());
  }
}

TEST(EnumField, ConsumeIntoMemberLeavesRemainingData) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  ExampleStruct s;
  s.enum_field = static_cast<MyEnum>(999);
  std::string serialized =
      absl::StrCat(HexDecodeOrDie("8001"), "remaining data");
  ParsingState parsing_state = ParsingState(serialized);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsOk());
  EXPECT_THAT(s.enum_field, Eq(static_cast<MyEnum>(128)));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining data"));
}

TEST(EnumField, ConsumeIntoMemberFailureCases) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  ExampleStruct s;

  for (std::string test_case :
       {"", /* 11 bytes, too long */ "ffffffffffffffffffff01"}) {
    SCOPED_TRACE(test_case);
    std::string serialized = HexDecodeOrDie(test_case);
    ParsingState parsing_state = ParsingState(serialized);
    EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), Not(IsOk()));
  }
}

TEST(EnumField, ConsumeIntoMemberInvalidFails) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &IsZeroOrOne);
  ExampleStruct s;
  std::string serialized = HexDecodeOrDie(/* 128 as varint */"8001");
  ParsingState parsing_state = ParsingState(serialized);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), Not(IsOk()));
}

TEST(EnumField, SerializeVarintSuccessCases) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  ExampleStruct s;

  for (std::pair<std::string, uint32_t> test_case : GetUint32TestCases()) {
    SCOPED_TRACE(test_case.first);
    std::string expected_serialization =
        HexDecodeOrDie(absl::StrCat("08", test_case.first));
    s.enum_field = static_cast<MyEnum>(test_case.second);
    ASSERT_THAT(field.GetSerializedSizeIncludingTag(s),
                Eq(expected_serialization.size()));

    std::string buffer;
    buffer.resize(expected_serialization.size());
    SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(buffer_span, s), IsOk());
    EXPECT_THAT(buffer, Eq(expected_serialization));
    EXPECT_THAT(buffer_span.GetBuffer().size(), Eq(0));
  }
}

TEST(Uint32Field, SerializeEmpty) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  std::string buffer = "abcdef";
  SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
  ExampleStruct s;
  s.enum_field = MyEnum::k0;

  ASSERT_THAT(field.GetSerializedSizeIncludingTag(s), Eq(0));
  EXPECT_THAT(field.SerializeWithTagInto(buffer_span, s), IsOk());
  std::string expected = "abcdef";
  // Note: absl::MakeSpan("abcdef").size() == 7 (will add null terminator).
  EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
}

TEST(Uint32Field, SerializeEmptyAlwaysSerialize) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid,
                                         ProtoFieldOptions::kAlwaysSerialize);
  std::string buffer = "abcdef";
  SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
  ExampleStruct s;
  s.enum_field = MyEnum::k0;

  ASSERT_THAT(field.GetSerializedSizeIncludingTag(s), Eq(2));
  EXPECT_THAT(field.SerializeWithTagInto(buffer_span, s), IsOk());
  std::string expected = "cdef";
  // Note: absl::MakeSpan("cdef").size() == 5 (will add null terminator).
  EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
  EXPECT_THAT(HexEncode(buffer.substr(0, 2)), Eq("0800"));
}

TEST(EnumField, SerializeVarintBufferTooSmall) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  ExampleStruct s;
  for (std::pair<std::string, uint32_t> test_case : GetUint32TestCases()) {
    SCOPED_TRACE(test_case.first);
    s.enum_field = static_cast<MyEnum>(test_case.second);
    ASSERT_THAT(field.GetSerializedSizeIncludingTag(s),
                Eq(test_case.first.size() / 2 + 1));

    std::string buffer;
    buffer.resize(test_case.first.size() / 2);
    SerializationState state = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(state, s), Not(IsOk()));
  }
}

TEST(EnumField, SerializeVarintLeavesRemainingData) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  std::string buffer = "abcdef";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  ExampleStruct s;
  s.enum_field = static_cast<MyEnum>(14882);
  // Will overwrite the first two bytes with 0xa274
  EXPECT_THAT(field.SerializeWithTagInto(state, s), IsOk());
  EXPECT_THAT(HexEncode(buffer), Eq("08a274646566"));
  std::string expected = "def";
  // Note: absl::MakeSpan("def").size() == 4 (will add null terminator).
  EXPECT_THAT(state.GetBuffer(), Eq(absl::MakeSpan(expected)));
}

TEST(EnumField, GetFieldNumber) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  ASSERT_THAT(field.GetFieldNumber(), Eq(1));
  EnumField<ExampleStruct, MyEnum> field2(2, &ExampleStruct::enum_field,
                                          &IsZeroOrOne);
  ASSERT_THAT(field2.GetFieldNumber(), Eq(2));
}

}  // namespace
}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
