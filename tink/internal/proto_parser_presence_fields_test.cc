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

#include "tink/internal/proto_parser_presence_fields.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
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
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::Optional;
using ::testing::Test;

struct ParsedStruct {
  absl::optional<uint32_t> uint32_member_1;
};

TEST(Uint32FieldWithPresence, ClearMemberWorks) {
  Uint32FieldWithPresence<ParsedStruct> field(1,
                                              &ParsedStruct::uint32_member_1);
  ParsedStruct s;
  s.uint32_member_1 = 123;
  field.ClearMember(s);
  EXPECT_THAT(s.uint32_member_1, Eq(absl::nullopt));
}

TEST(Uint32FieldWithPresence, ConsumeIntoMemberSuccessCases) {
  Uint32FieldWithPresence<ParsedStruct> field(1,
                                              &ParsedStruct::uint32_member_1);
  ParsedStruct s;
  s.uint32_member_1 = absl::nullopt;
  std::string serialized =
      absl::StrCat(HexDecodeOrDie("8001"), "remaining data");
  ParsingState parsing_state = ParsingState(serialized);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
  EXPECT_THAT(s.uint32_member_1, Optional(128));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining data"));
}

TEST(Uint32FieldWithPresence, ConsumeIntoMemberFailureCases) {
  Uint32FieldWithPresence<ParsedStruct> field(1,
                                              &ParsedStruct::uint32_member_1);
  ParsedStruct s;

  for (std::string test_case :
       {"", "faab",
        /* valid uint_64 encoding: */ "ffffffffffffffffffff01"}) {
    SCOPED_TRACE(test_case);
    std::string serialized = HexDecodeOrDie(test_case);
    ParsingState parsing_state = ParsingState(serialized);
    EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsFalse());
  }
}

TEST(Uint32FieldWithPresence, SerializeSuccessCases) {
  Uint32FieldWithPresence<ParsedStruct> field(1,
                                              &ParsedStruct::uint32_member_1);
  ParsedStruct s;

  for (std::pair<std::string, uint32_t> test_case :
       std::vector<std::pair<std::string, uint32_t>>{
           {"00", 0}, {"01", 1}, {"7f", 127}, {"8001", 128}, {"a274", 14882}}) {
    SCOPED_TRACE(test_case.first);
    std::string expected_serialization =
        HexDecodeOrDie(absl::StrCat("08", test_case.first));
    s.uint32_member_1 = test_case.second;
    ASSERT_THAT(field.GetSerializedSizeIncludingTag(s),
                Eq(expected_serialization.size()));

    std::string buffer;
    buffer.resize(expected_serialization.size());
    SerializationState state = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(state, s), IsOk());
    EXPECT_THAT(buffer, Eq(expected_serialization));
    EXPECT_THAT(state.GetBuffer().size(), Eq(0));
  }
}

TEST(Uint32FieldWithPresence, SerializeNullopt) {
  Uint32FieldWithPresence<ParsedStruct> field(1,
                                              &ParsedStruct::uint32_member_1);
  ParsedStruct s;

  s.uint32_member_1 = absl::nullopt;
  ASSERT_THAT(field.GetSerializedSizeIncludingTag(s), Eq(0));

  std::string buffer;
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(0));
}

TEST(Uint32FieldWithPresence, SerializeVarintBufferTooSmall) {
  Uint32FieldWithPresence<ParsedStruct> field(1,
                                              &ParsedStruct::uint32_member_1);
  ParsedStruct s;
  s.uint32_member_1 = 14882;  // Requires 2 bytes
  ASSERT_THAT(field.GetSerializedSizeIncludingTag(s),
              Eq(3));  // 1 for the tag, 2 for the data

  std::string buffer;
  buffer.resize(2);
  SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(buffer_span, s), Not(IsOk()));
}

TEST(Uint32FieldWithPresence, SerializeLeavesRemainingData) {
  Uint32FieldWithPresence<ParsedStruct> field(1,
                                              &ParsedStruct::uint32_member_1);
  std::string buffer = "abcdef";
  SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
  ParsedStruct s;
  s.uint32_member_1 = 14882;
  // Will overwrite the first two bytes with 0xa274
  EXPECT_THAT(field.SerializeWithTagInto(buffer_span, s), IsOk());
  EXPECT_THAT(HexEncode(buffer), Eq("08a274646566"));
  std::string expected = "def";
  // Note: absl::MakeSpan("def").size() == 4 (will add null terminator).
  EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
}

TEST(Uint32FieldWithPresence, GetFieldNumber) {
  Uint32FieldWithPresence<ParsedStruct> field(1,
                                              &ParsedStruct::uint32_member_1);
  ASSERT_THAT(field.GetFieldNumber(), Eq(1));
  Uint32FieldWithPresence<ParsedStruct> field2(2,
                                               &ParsedStruct::uint32_member_1);
  ASSERT_THAT(field2.GetFieldNumber(), Eq(2));
}

TEST(OptionalUint32Field, Clear) {
  OptionalUint32Field field(1);
  field.set_value(123);
  field.Clear();
  EXPECT_THAT(field.value(), Eq(absl::nullopt));
}

TEST(OptionalUint32Field, ConsumeIntoMemberSuccessCases) {
  OptionalUint32Field field(1);
  field.set_value(123);
  std::string serialized =
      absl::StrCat(HexDecodeOrDie("8001"), "remaining data");
  ParsingState parsing_state = ParsingState(serialized);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.value(), Optional(128));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining data"));
}

TEST(OptionalUint32Field, ConsumeIntoMemberFailureCases) {
  OptionalUint32Field field(1);

  for (std::string test_case :
       {"", "faab",
        /* valid uint_64 encoding: */ "ffffffffffffffffffff01"}) {
    SCOPED_TRACE(test_case);
    std::string serialized = HexDecodeOrDie(test_case);
    ParsingState parsing_state = ParsingState(serialized);
    EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
  }
}

TEST(OptionalUint32Field, GetSerializedSize) {
  OptionalUint32Field field(1);
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
  field.set_value(1);
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(2));
  field.set_value(128);
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(3));
}

TEST(OptionalUint32Field, SerializeWithNoValue) {
  OptionalUint32Field field(1);
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
  std::string buffer;
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(0));
}

TEST(OptionalUint32Field, SerializeWithZero) {
  OptionalUint32Field field(1);
  field.set_value(0);
  std::string expected_serialization = HexDecodeOrDie("0800");
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(),
              Eq(expected_serialization.size()));
  std::string buffer;
  buffer.resize(expected_serialization.size());
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(buffer, Eq(expected_serialization));
  EXPECT_THAT(state.GetBuffer().size(), Eq(0));
}

TEST(OptionalUint32Field, SerializeWithValue) {
  OptionalUint32Field field(1);
  field.set_value(128);
  std::string expected_serialization = HexDecodeOrDie("088001");
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(),
              Eq(expected_serialization.size()));
  std::string buffer;
  buffer.resize(expected_serialization.size());
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(buffer, Eq(expected_serialization));
  EXPECT_THAT(state.GetBuffer().size(), Eq(0));
}

TEST(OptionalUint32Field, SerializeWithValueTooSmallBuffer) {
  OptionalUint32Field field(1);
  field.set_value(128);
  std::string expected_serialization = HexDecodeOrDie("088001");
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(),
              Eq(expected_serialization.size()));
  std::string buffer;
  buffer.resize(expected_serialization.size() - 1);
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

}  // namespace
}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
