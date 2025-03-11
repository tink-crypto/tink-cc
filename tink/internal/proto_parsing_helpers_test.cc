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

#include "tink/internal/proto_parsing_helpers.h"

#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
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
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::SecretData;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::Test;

struct VarintCase {
  absl::string_view hex_encoded_bytes;  // Encoding
  uint64_t value;                       // Parsed value.
};

std::vector<VarintCase> VarintFieldParseAndSerializeCases() {
  return std::vector<VarintCase>({
      {"00", 0},
      {"01", 1},
      {"7f", 127},
      {"8001", 128},
      {"a274", 14882},
      {"ff7f", 16383},
      {"808001", 16384},
      {"ffff7f", 2097151},
      {"80808001", 2097152},
      {"bef792840b", 2961488830},
      {"80e6eb9cc3c9a449", 41256202580718336ULL},
      {"9ba8f9c2bbd68085a601", 11964378330978735131ULL},
      {"80808080808080808001", /* 2^63 */ 9223372036854775808ULL},
      {"feffffffffffffffff01", /* 2^64 - 2*/ 18446744073709551614ULL},
      {"ffffffffffffffffff01", /* 2^64 - 1*/ 18446744073709551615ULL},
  });
}

std::vector<VarintCase> VarintFieldParseCases() {
  std::vector<VarintCase> result = VarintFieldParseAndSerializeCases();
  result.push_back({"8000", 0});
  result.push_back({"80808080808080808000", 0});
  result.push_back({"80818000", 128});
  result.push_back({"ffffffffffffffffff7f", 18446744073709551615ULL});
  return result;
}

TEST(ProtoParserTest, ConsumeVarintIntoUint64DirectTest) {
  for (const VarintCase& v : VarintFieldParseCases()) {
    SCOPED_TRACE(v.value);
    std::string bytes = HexDecodeOrDie(v.hex_encoded_bytes);
    ParsingState parsing_state = ParsingState(bytes);
    absl::StatusOr<uint64_t> result = ConsumeVarintIntoUint64(parsing_state);
    ASSERT_THAT(result, IsOk());
    EXPECT_THAT(*result, Eq(v.value));
    EXPECT_THAT(parsing_state.RemainingData(), IsEmpty());
  }
}

TEST(ProtoParserTest, ConsumeVarintIntoUint32DirectTest) {
  for (const VarintCase& v : VarintFieldParseCases()) {
    SCOPED_TRACE(v.value);
    std::string bytes = HexDecodeOrDie(v.hex_encoded_bytes);
    ParsingState parsing_state = ParsingState(bytes);
    absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(parsing_state);
    ASSERT_THAT(result, IsOk());
    EXPECT_THAT(*result, Eq(static_cast<uint32_t>(v.value)));
    EXPECT_THAT(parsing_state.RemainingData(), IsEmpty());
  }
}

TEST(VarintLength, VarintCases) {
  for (const VarintCase& v : VarintFieldParseAndSerializeCases()) {
    SCOPED_TRACE(v.value);
    EXPECT_THAT(VarintLength(v.value), Eq(v.hex_encoded_bytes.size() / 2));
  }
}

TEST(SerializeVarint, VarintCases) {
  for (const VarintCase& v : VarintFieldParseAndSerializeCases()) {
    SCOPED_TRACE(v.value);
    std::string output;
    output.resize(VarintLength(v.value));
    SerializationState output_span = SerializationState(absl::MakeSpan(output));
    EXPECT_THAT(SerializeVarint(v.value, output_span), IsOk());
    EXPECT_THAT(HexEncode(output), Eq(v.hex_encoded_bytes));
    EXPECT_THAT(output_span.GetBuffer(), IsEmpty());
  }
}

TEST(SerializeVarint, LeavesUnusedBytes) {
  std::string output = "abcdef";
  SerializationState output_span = SerializationState(absl::MakeSpan(output));
  // Will overwrite the first two bytes with 0xa274
  EXPECT_THAT(SerializeVarint(14882, output_span), IsOk());
  EXPECT_THAT(HexEncode(output), Eq("a27463646566"));
  std::string expected = "cdef";
  // Note: absl::MakeSpan("cdef").size() == 5 (will add null terminator).
  EXPECT_THAT(output_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
}

TEST(SerializeVarint, TooSmallOutputBuffer) {
  std::string output_buffer = "abcdefghijklmnop";
  for (const VarintCase& v : VarintFieldParseAndSerializeCases()) {
    SCOPED_TRACE(v.value);
    absl::Span<char> output_span = absl::MakeSpan(output_buffer);
    output_span = output_span.subspan(0, VarintLength(v.value) - 1);
    SerializationState serialization_state = SerializationState(output_span);
    EXPECT_THAT(SerializeVarint(v.value, serialization_state), Not(IsOk()));
  }
}

constexpr absl::string_view kHexEncodedVarintFailureCases[] = {
    "",
    // Varint with too many bytes.
    "ffffffffffffffffffff01",
};

TEST(ProtoParserTest, VarintParsingFailure) {
  for (absl::string_view hex_encoded_bytes : kHexEncodedVarintFailureCases) {
    SCOPED_TRACE(hex_encoded_bytes);
    std::string bytes = HexDecodeOrDie(hex_encoded_bytes);
    ParsingState parsing_state = ParsingState(bytes);
    EXPECT_THAT(ConsumeVarintIntoUint64(parsing_state), Not(IsOk()));
  }
}

struct WireTypeAndFieldNumberCase {
  absl::string_view hex_encoded_bytes;  // Encoding
  WireType wiretype;
  int field_number;
};

// Test cases which work for both parsing and serialization.
std::vector<WireTypeAndFieldNumberCase> CanonicalWireTypeAndTagCases() {
  return {
      {"08", WireType::kVarint, 1},
      {"09", WireType::kFixed64, 1},
      {"0a", WireType::kLengthDelimited, 1},
      {"0b", WireType::kStartGroup, 1},
      {"0c", WireType::kEndGroup, 1},
      {"0d", WireType::kFixed32, 1},
      {"10", WireType::kVarint, 2},
      {"78", WireType::kVarint, 15},
      {"8001", WireType::kVarint, 16},
      {"f8ffffff0f", WireType::kVarint, 536870911},
  };
}

// Test cases which work only for parsing, but not serialization.
std::vector<WireTypeAndFieldNumberCase>
CanonicalAndParseableWireTypeAndTagCases() {
  std::vector<WireTypeAndFieldNumberCase> result =
      CanonicalWireTypeAndTagCases();
  // Normal 0x08 but with lots of padded zeros
  result.push_back({"8880808000", WireType::kVarint, 1});
  // 0x08 + 2^32
  result.push_back({"8880808010", WireType::kVarint, 1});
  // 0x08 + 7 * 2^32
  result.push_back({"8880808070", WireType::kVarint, 1});
  // 0xf8ffffff0f + 2^32
  result.push_back({"f8ffffff1f", WireType::kVarint, 536870911});
  // 0xf8ffffff0f + 7 * 2^32
  result.push_back({"f8ffffff7f", WireType::kVarint, 536870911});
  return result;
}

TEST(ProtoParserTest, ConsumeIntoWireTypeAndFieldNumber) {
  for (const WireTypeAndFieldNumberCase& v :
       CanonicalAndParseableWireTypeAndTagCases()) {
    SCOPED_TRACE(v.hex_encoded_bytes);
    std::string bytes = HexDecodeOrDie(v.hex_encoded_bytes);
    ParsingState parsing_state = ParsingState(bytes);
    absl::StatusOr<std::pair<WireType, int>> result =
        ConsumeIntoWireTypeAndFieldNumber(parsing_state);
    ASSERT_THAT(result, IsOk());
    EXPECT_THAT(result->first, Eq(v.wiretype));
    EXPECT_THAT(result->second, Eq(v.field_number));
    EXPECT_THAT(parsing_state.RemainingData(), IsEmpty());
  }
}

TEST(ProtoParserTest, ConsumeIntoWireTypeAndFieldNumberFailures) {
  for (const absl::string_view v :
       std::vector<absl::string_view>({"00", "f8ffffffff7f"})) {
    SCOPED_TRACE(v);
    std::string bytes = HexDecodeOrDie(v);
    ParsingState parsing_state = ParsingState(bytes);
    EXPECT_THAT(ConsumeIntoWireTypeAndFieldNumber(parsing_state), Not(IsOk()));
  }
}

TEST(ProtoParserTest, SerializeIntoWireTypeAndTagSuccess) {
  for (const WireTypeAndFieldNumberCase& v : CanonicalWireTypeAndTagCases()) {
    SCOPED_TRACE(v.hex_encoded_bytes);
    std::string buffer;
    buffer.resize(WireTypeAndFieldNumberLength(v.wiretype, v.field_number));
    SerializationState state = SerializationState(absl::MakeSpan(buffer));
    if (v.field_number > 0 && v.field_number < /* 2^29 = */ 536870912) {
      EXPECT_THAT(SerializeWireTypeAndFieldNumber(v.wiretype, v.field_number,
                                                  state),
                  IsOk());
      EXPECT_THAT(HexEncode(buffer), Eq(v.hex_encoded_bytes));
      EXPECT_THAT(state.GetBuffer(), IsEmpty());
    } else {
      EXPECT_THAT(SerializeWireTypeAndFieldNumber(v.wiretype, v.field_number,
                                                  state),
                  Not(IsOk()));
    }
  }
}

TEST(ConsumeVarintForSize, ValidInput) {
  std::string bytes = absl::StrCat(HexDecodeOrDie("0a"), "def");
  ParsingState parsing_state = ParsingState(bytes);
  absl::StatusOr<uint32_t> result =
      ConsumeVarintForSize(parsing_state);
  ASSERT_THAT(result, IsOkAndHolds(10));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("def"));
}

TEST(ConsumeVarintForSize, VariousValidInputs) {
  std::vector<std::pair<std::string, uint32_t>> input_and_results = {
      {"00", 0},
      // Up to 5 byte long values can be arbitrarily padded
      {"8000", 0},
      {"8080808000", 0},
      {"01", 1},
      {"8180808000", 1},
      {"ff7f", 0x3fff},
      // Values up to 2^32 - 1 are allowed
      {"ffffffff0f", 0xffffffff},
      // An arbitrary value
      {"abcd8107", 0xe066ab}
  };
  for (std::pair<std::string, int> input_and_result : input_and_results) {
    std::string bytes = HexDecodeOrDie(input_and_result.first);
    ParsingState parsing_state = ParsingState(bytes);
    absl::StatusOr<uint32_t> result =
        ConsumeVarintForSize(parsing_state);
    ASSERT_THAT(result, IsOkAndHolds(Eq(input_and_result.second)));
    EXPECT_THAT(parsing_state.RemainingData(), Eq(""));
  }
}

TEST(ConsumeVarintForSize, InvalidVarints) {
  std::vector<std::string> invalid_inputs = {
      // 6 bytes are always rejected
      "808080808000",
      // All values greater than 2^32-1 are rejected (which means bit 5 in the
      // 5th byte has to be set)
      "ffffffff1f",
      "8080808010",
  };
  for (std::string input : invalid_inputs) {
    std::string bytes = HexDecodeOrDie(input);
    ParsingState parsing_state = ParsingState(bytes);
    EXPECT_THAT(ConsumeVarintForSize(parsing_state), Not(IsOk()));
  }
}

TEST(ConsumeBytesReturnStringView, ValidInput) {
  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  ParsingState parsing_state = ParsingState(bytes);
  absl::StatusOr<absl::string_view> result =
      ConsumeBytesReturnStringView(parsing_state);
  ASSERT_THAT(result, IsOk());
  EXPECT_THAT(*result, Eq("1234567890"));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("XYZ"));
}

TEST(ConsumeBytesReturnStringView, EmptyString) {
  std::string bytes = absl::StrCat(/* 0 bytes */ HexDecodeOrDie("00"), "abcde");
  ParsingState parsing_state = ParsingState(bytes);
  absl::StatusOr<absl::string_view> result =
      ConsumeBytesReturnStringView(parsing_state);
  ASSERT_THAT(result, IsOk());
  EXPECT_THAT(*result, Eq(""));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("abcde"));
}

TEST(ConsumeBytesReturnStringView, EmptyWithoutVarint) {
  ParsingState parsing_state = ParsingState("");
  ASSERT_THAT(ConsumeBytesReturnStringView(parsing_state), Not(IsOk()));
}

TEST(ConsumeBytesReturnStringView, PaddedVarint) {
  std::string bytes =
      absl::StrCat(/* 0 bytes */ HexDecodeOrDie("8000"), "abcde");
  ParsingState parsing_state = ParsingState(bytes);
  absl::StatusOr<absl::string_view> result =
      ConsumeBytesReturnStringView(parsing_state);
  ASSERT_THAT(result, IsOk());
  ASSERT_THAT(parsing_state.RemainingData(), Eq("abcde"));
}

TEST(ConsumeBytesReturnStringView, VeryPaddedVarint) {
  std::string bytes =
      absl::StrCat(/* 0 bytes */ HexDecodeOrDie("808080808000"), "abcde");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(ConsumeBytesReturnStringView(parsing_state).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("more than 5 bytes")));
}

TEST(ConsumeBytesReturnStringView, InvalidVarint) {
  std::string bytes =
      absl::StrCat(/* 0 bytes */ HexDecodeOrDie("8080808010"), "abcde");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(ConsumeBytesReturnStringView(parsing_state).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("declared to be longer than 2^32-1")));
}

TEST(ConsumeFixed32, Consumes4Bytes) {
  std::string bytes = "1234567";
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(ConsumeFixed32(parsing_state), IsOk());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("567"));
  ASSERT_THAT(ConsumeFixed32(parsing_state), Not(IsOk()));
}

TEST(ConsumeFixed64, Consumes8Bytes) {
  std::string bytes = "0abc4abc8abc2ab";
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(ConsumeFixed64(parsing_state), IsOk());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("8abc2ab"));
  ASSERT_THAT(ConsumeFixed64(parsing_state), Not(IsOk()));
}

TEST(SkipField, Fixed32) {
  std::string bytes = "1234567";
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipField(WireType::kFixed32, parsing_state), IsOk());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("567"));
  ASSERT_THAT(SkipField(WireType::kFixed32, parsing_state), Not(IsOk()));
}

TEST(SkipField, Fixed64) {
  std::string bytes = "0abc4abc8abc2ab";
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipField(WireType::kFixed64, parsing_state), IsOk());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("8abc2ab"));
  ASSERT_THAT(SkipField(WireType::kFixed64, parsing_state), Not(IsOk()));
}

TEST(SkipField, Varint) {
  std::string bytes = HexDecodeOrDie("08");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipField(WireType::kVarint, parsing_state), IsOk());
  EXPECT_THAT(parsing_state.RemainingData(), Eq(""));
  ASSERT_THAT(SkipField(WireType::kVarint, parsing_state), Not(IsOk()));
}

TEST(SkipField, VarintRemainder) {
  std::string bytes = HexDecodeOrDie("8808aa");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipField(WireType::kVarint, parsing_state), IsOk());
  EXPECT_THAT(HexEncode(parsing_state.RemainingData()), Eq("aa"));
}

TEST(SkipField, VarintFail) {
  std::string bytes = HexDecodeOrDie("888888");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipField(WireType::kVarint, parsing_state), Not(IsOk()));
}

TEST(SkipField, LengthEncoded) {
  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipField(WireType::kLengthDelimited, parsing_state), IsOk());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("XYZ"));
}

TEST(SkipField, LengthEncodedTooShort) {
  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "123456789");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipField(WireType::kLengthDelimited, parsing_state),
              Not(IsOk()));
}

TEST(SkipField, StartGroupFails) {
  std::string bytes = "some bytes";
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipField(WireType::kStartGroup, parsing_state), Not(IsOk()));
}
TEST(SkipField, EndGroupFalis) {
  std::string bytes = "some bytes";
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipField(WireType::kEndGroup, parsing_state), Not(IsOk()));
}

/* 3b: start group (field #7): 3 + 7 * 8 = 59 = 0x3b */
/* 3c:   end group (field #7): 4 + 7 * 8 = 60 = 0x3c */
/* 43: start group (field #8): 3 + 8 * 8 = 59 = 0x43 */
/* 44:   end group (field #8): 4 + 8 * 8 = 60 = 0x44 */
TEST(SkipGroup, BasicWorks) {
  std::string bytes = HexDecodeOrDie("3c");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipGroup(7, parsing_state), IsOk());
  EXPECT_THAT(parsing_state.RemainingData(), Eq(""));
}

TEST(SkipGroup, LeftOversAreKept) {
  std::string bytes = absl::StrCat(HexDecodeOrDie("3c"), "leftover");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipGroup(7, parsing_state), IsOk());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("leftover"));
}

TEST(SkipGroup, WrongClosingTagFails) {
  std::string bytes = HexDecodeOrDie("44");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipGroup(7, parsing_state), Not(IsOk()));
}

TEST(SkipGroup, NestedWorks) {
  std::string bytes = HexDecodeOrDie("433b3c443c");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipGroup(7, parsing_state), IsOk());
  EXPECT_THAT(parsing_state.RemainingData(), Eq(""));
}

TEST(SkipGroup, BadNestingFails) {
  std::string bytes = HexDecodeOrDie("433c44");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipGroup(7, parsing_state), Not(IsOk()));
}

TEST(SkipGroup, NestedStringFieldWorks) {
  std::string bytes = HexDecodeOrDie(absl::StrCat(
      /* kLengthDelimited, tag#1 = */ "0a",
      /* 10 bytes length encoded */ "0a", "12345678901234567890", "3c"));
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipGroup(7, parsing_state), IsOk());
  EXPECT_THAT(parsing_state.RemainingData(), Eq(""));
}

TEST(SkipGroup, NestedStringFieldTooShort) {
  std::string bytes = HexDecodeOrDie(absl::StrCat(
      /* kLengthDelimited, tag#1 = */ "0a",
      /* 10 bytes length encoded */ "0a", "1234567812345678", "3c"));
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipGroup(7, parsing_state), Not(IsOk()));
}

TEST(SkipGroup, NestedVarintFieldWorks) {
  std::string bytes = HexDecodeOrDie(absl::StrCat(
      /* kVarint, tag#1 = */ "08",
      /* Varint value 1 */ "08", "3c"));
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipGroup(7, parsing_state), IsOk());
  EXPECT_THAT(parsing_state.RemainingData(), Eq(""));
}

TEST(SkipGroup, NestedFixed64FieldWorks) {
  std::string bytes = HexDecodeOrDie(absl::StrCat(
      /* kFixed64, tag#1 = */ "09",
      /* Varint value 1 */ "0011223344556677", "3c"));
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipGroup(7, parsing_state), IsOk());
  EXPECT_THAT(parsing_state.RemainingData(), Eq(""));
}

TEST(SkipGroup, NestedFixed32FieldWorks) {
  std::string bytes = HexDecodeOrDie(absl::StrCat(
      /* kFixed32, tag#1 = */ "0d",
      /* Varint value 1 */ "00112233", "3c"));
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(SkipGroup(7, parsing_state), IsOk());
  EXPECT_THAT(parsing_state.RemainingData(), Eq(""));
}

}  // namespace

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
