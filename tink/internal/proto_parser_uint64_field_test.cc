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
#include "tink/internal/proto_parser_uint64_field.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/util/test_util.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::HexEncode;
using ::crypto::tink::test::IsOk;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;

struct ParsedStruct {
  uint64_t field1;
};

std::vector<std::pair<std::string, uint64_t>>
Uint64TestCasesParseAndSerialize() {
  return std::vector<std::pair<std::string, uint64_t>>{
      {"01", 1},
      {"7f", 127},
      {"8001", 128},
      {"a274", 14882},
      {"ffffffff0f", 0xffffffffLL},
      {"8080808010", 0x100000000LL},
      {"f0bdf3d589cf959a12", 0x123456789abcdef0LL},
      {"ffffffffffffffff7f", 0x7fffffffffffffffLL},
      {"ffffffffffffffffff01", 0xffffffffffffffffLL},
  };
}

std::vector<std::pair<std::string, uint64_t>> Uint64TestCasesParseOnly() {
  std::vector<std::pair<std::string, uint64_t>> result =
      Uint64TestCasesParseAndSerialize();
  result.push_back({"00", 0});
  // Padded up to 10 bytes.
  result.push_back({"8000", 0});
  result.push_back({"80808080808080808000", 0});
  result.push_back({"8100", 1});
  result.push_back({"ffffffffffffffffff0f", 0xFFFFFFFFFFFFFFFFLL});
  result.push_back({"ffffffffffffffffff7f", 0xFFFFFFFFFFFFFFFFLL});
  return result;
}

TEST(Uint64Field, ClearMemberWorks) {
  Uint64Field<ParsedStruct> field(1, &ParsedStruct::field1);
  ParsedStruct s;
  s.field1 = 123;
  field.ClearMember(s);
  EXPECT_THAT(s.field1, testing::Eq(0));
}

TEST(Uint64Field, ConsumeIntoMemberSuccessCases) {
  Uint64Field<ParsedStruct> field(1, &ParsedStruct::field1);
  ParsedStruct s;
  s.field1 = 999;

  for (std::pair<std::string, uint64_t> test_case :
       Uint64TestCasesParseOnly()) {
    SCOPED_TRACE(test_case.first);
    std::string serialized = HexDecodeOrDie(test_case.first);
    ParsingState parsing_state = ParsingState(serialized);
    EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
    EXPECT_THAT(s.field1, Eq(test_case.second));
    EXPECT_THAT(parsing_state.RemainingData(), IsEmpty());
  }
}

TEST(Uint64Field, ConsumeIntoMemberLeavesRemainingData) {
  Uint64Field<ParsedStruct> field(1, &ParsedStruct::field1);
  ParsedStruct s;
  s.field1 = 999;
  std::string serialized =
      absl::StrCat(HexDecodeOrDie("8001"), "remaining data");
  ParsingState parsing_state = ParsingState(serialized);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
  EXPECT_THAT(s.field1, Eq(128));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining data"));
}

TEST(Uint64Field, ConsumeIntoMemberFailureCases) {
  Uint64Field<ParsedStruct> field(1, &ParsedStruct::field1);
  ParsedStruct s;

  for (std::string test_case : {"", "faab"}) {
    SCOPED_TRACE(test_case);
    std::string serialized = HexDecodeOrDie(test_case);
    ParsingState parsing_state = ParsingState(serialized);
    EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsFalse());
  }
}

TEST(Uint64Field, SerializeVarintSuccessCases) {
  Uint64Field<ParsedStruct> field(1, &ParsedStruct::field1);
  ParsedStruct s;

  for (std::pair<std::string, uint64_t> test_case :
       Uint64TestCasesParseAndSerialize()) {
    SCOPED_TRACE(test_case.first);
    std::string expected_serialization =
        HexDecodeOrDie("08") + HexDecodeOrDie(test_case.first);
    s.field1 = test_case.second;
    EXPECT_THAT(field.GetSerializedSizeIncludingTag(s),
                Eq(expected_serialization.size()));

    std::string buffer;
    buffer.resize(expected_serialization.size());
    SerializationState state = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(state, s), IsOk());
    EXPECT_THAT(HexEncode(buffer), Eq(HexEncode(expected_serialization)));
    EXPECT_THAT(state.GetBuffer().size(), Eq(0));
  }
}

TEST(Uint64Field, SerializeVarintDifferentFieldNumberSuccessCases) {
  Uint64Field<ParsedStruct> field(12345, &ParsedStruct::field1);
  ParsedStruct s;

  for (std::pair<std::string, uint64_t> test_case :
       Uint64TestCasesParseAndSerialize()) {
    SCOPED_TRACE(test_case.first);
    std::string expected_serialization =
        HexDecodeOrDie("c88306") + HexDecodeOrDie(test_case.first);
    s.field1 = test_case.second;
    EXPECT_THAT(field.GetSerializedSizeIncludingTag(s),
                Eq(expected_serialization.size()));

    std::string buffer;
    buffer.resize(expected_serialization.size());
    SerializationState state = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(state, s), IsOk());
    EXPECT_THAT(HexEncode(buffer), Eq(HexEncode(expected_serialization)));
    EXPECT_THAT(state.GetBuffer().size(), Eq(0));
  }
}

TEST(Uint64Field, SerializeVarintBufferTooSmall) {
  Uint64Field<ParsedStruct> field(1, &ParsedStruct::field1);
  ParsedStruct s;
  for (std::pair<std::string, uint64_t> test_case :
       Uint64TestCasesParseAndSerialize()) {
    SCOPED_TRACE(test_case.first);
    s.field1 = test_case.second;
    ASSERT_THAT(field.GetSerializedSizeIncludingTag(s),
                Eq(test_case.first.size() / 2 + 1));

    std::string buffer;
    buffer.resize(test_case.first.size() / 2);
    SerializationState state = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(state, s), Not(IsOk()));
  }
}

TEST(Uint64Field, SerializeVarintLeavesRemainingData) {
  Uint64Field<ParsedStruct> field(1, &ParsedStruct::field1);
  std::string buffer = "abcdef";
  SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
  ParsedStruct s;
  s.field1 = 14882;
  // Will overwrite the first two bytes with 0xa274
  EXPECT_THAT(field.SerializeWithTagInto(buffer_span, s), IsOk());
  EXPECT_THAT(HexEncode(buffer), Eq("08a274646566"));
  std::string expected = "def";
  // Note: absl::MakeSpan("def").size() == 4 (will add null terminator).
  EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
}

TEST(Uint64Field, Empty) {
  Uint64Field<ParsedStruct> field(1, &ParsedStruct::field1);
  std::string buffer = "abcdef";
  SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
  ParsedStruct s;
  s.field1 = 0;

  ASSERT_THAT(field.GetSerializedSizeIncludingTag(s), Eq(0));
  EXPECT_THAT(field.SerializeWithTagInto(buffer_span, s), IsOk());
  std::string expected = "abcdef";
  // Note: absl::MakeSpan("abcdef").size() == 7 (will add null terminator).
  EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
}

TEST(Uint64Field, GetFieldNumber) {
  Uint64Field<ParsedStruct> field(1, &ParsedStruct::field1);
  ASSERT_THAT(field.GetFieldNumber(), Eq(1));
  Uint64Field<ParsedStruct> field2(2, &ParsedStruct::field1);
  ASSERT_THAT(field2.GetFieldNumber(), Eq(2));
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

