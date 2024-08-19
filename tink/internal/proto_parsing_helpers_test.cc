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
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
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
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::StatusOr;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::Test;

struct VarintCase {
  absl::string_view hex_encoded_bytes;  // Encoding
  uint64_t value;                       // Parsed value.
};

constexpr VarintCase kVarintCases[] = {
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
    {"80808080808080808001", /* 2^63 */ 9223372036854775808ULL },
    {"feffffffffffffffff01", /* 2^64 - 2*/ 18446744073709551614ULL },
    {"ffffffffffffffffff01", /* 2^64 - 1*/ 18446744073709551615ULL },
};

TEST(ProtoParserTest, ConsumeVarintIntoUint64DirectTest) {
  for (const VarintCase& v : kVarintCases) {
    SCOPED_TRACE(v.value);
    std::string bytes = HexDecodeOrDie(v.hex_encoded_bytes);
    absl::string_view bytes_view = bytes;
    absl::StatusOr<uint64_t> result = ConsumeVarintIntoUint64(bytes_view);
    ASSERT_THAT(result, IsOk());
    EXPECT_THAT(*result, Eq(v.value));
    EXPECT_THAT(bytes_view, IsEmpty());
  }
}

TEST(ProtoParserTest, ConsumeVarintIntoUint32DirectTest) {
  for (const VarintCase& v : kVarintCases) {
    SCOPED_TRACE(v.value);
    std::string bytes = HexDecodeOrDie(v.hex_encoded_bytes);
    absl::string_view bytes_view = bytes;
    absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(bytes_view);
    if (v.value <= std::numeric_limits<uint32_t>::max()) {
      ASSERT_THAT(result, IsOk());
      EXPECT_THAT(*result, Eq(v.value));
      EXPECT_THAT(bytes_view, IsEmpty());
    } else {
      EXPECT_THAT(result, Not(IsOk()));
    }
  }
}

TEST(VarintLength, VarintCases) {
  for (const VarintCase& v : kVarintCases) {
    SCOPED_TRACE(v.value);
    EXPECT_THAT(VarintLength(v.value), Eq(v.hex_encoded_bytes.size()/2));
  }
}

TEST(SerializeVarint, VarintCases) {
  for (const VarintCase& v : kVarintCases) {
    SCOPED_TRACE(v.value);
    std::string output;
    output.resize(VarintLength(v.value));
    absl::Span<char> output_span = absl::MakeSpan(output);
    EXPECT_THAT(SerializeVarint(v.value, output_span), IsOk());
    EXPECT_THAT(HexEncode(output), Eq(v.hex_encoded_bytes));
    EXPECT_THAT(output_span, IsEmpty());
  }
}

TEST(SerializeVarint, LeavesUnusedBytes) {
  std::string output = "abcdef";
  absl::Span<char> output_span = absl::MakeSpan(output);
  // Will overwrite the first two bytes with 0xa274
  EXPECT_THAT(SerializeVarint(14882, output_span), IsOk());
  EXPECT_THAT(HexEncode(output),
              Eq("a27463646566"));
  std::string expected = "cdef";
  // Note: absl::MakeSpan("cdef").size() == 5 (will add null terminator).
  EXPECT_THAT(output_span, Eq(absl::MakeSpan(expected)));
}

TEST(SerializeVarint, TooSmallOutputBuffer) {
  std::string output_buffer = "abcdefghijklmnop";
  for (const VarintCase& v : kVarintCases) {
    SCOPED_TRACE(v.value);
    absl::Span<char> output_span = absl::MakeSpan(output_buffer);
    output_span = output_span.subspan(0, VarintLength(v.value) - 1);
    EXPECT_THAT(SerializeVarint(v.value, output_span), Not(IsOk()));
  }
}

constexpr absl::string_view kHexEncodedVarintFailureCases[] = {
    "",
    // We expect canonical varints: this encodes 0 so should be encoded as "0"
    "8000",
    // This encodes 1, so should be encoded as "01".
    "8100",
    "faab",
    "f0abc99af8b2",
    // Would encode 2^64 == std::numeric_limits<uint64_t>::max() + 1
    "80808080808080808002",
     // Something clearly too big (but the same number of bytes as above)
    "ffffffffffffffffff08",
     // Varint with too many bytes.
    "ffffffffffffffffffff01",
};

TEST(ProtoParserTest, VarintParsingFailure) {
  for (absl::string_view hex_encoded_bytes : kHexEncodedVarintFailureCases) {
    SCOPED_TRACE(hex_encoded_bytes);
    std::string bytes = HexDecodeOrDie(hex_encoded_bytes);
    absl::string_view bytes_view = bytes;
    EXPECT_THAT(ConsumeVarintIntoUint64(bytes_view), Not(IsOk()));
  }
}

struct WireTypeAndTagCase {
  absl::string_view hex_encoded_bytes;  // Encoding
  WireType wiretype;
  int tag;
};

constexpr WireTypeAndTagCase kWireTypeAndTagCases[] = {
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

TEST(ProtoParserTest, ConsumeIntoWireTypeAndTag) {
  for (const WireTypeAndTagCase& v : kWireTypeAndTagCases) {
    SCOPED_TRACE(v.hex_encoded_bytes);
    std::string bytes = HexDecodeOrDie(v.hex_encoded_bytes);
    absl::string_view bytes_view = bytes;
    absl::StatusOr<std::pair<WireType, int>> result =
        ConsumeIntoWireTypeAndTag(bytes_view);
    ASSERT_THAT(result, IsOk());
    EXPECT_THAT(result->first, Eq(v.wiretype));
    EXPECT_THAT(result->second, Eq(v.tag));
    EXPECT_THAT(bytes_view, IsEmpty());
  }
}

TEST(ProtoParserTest, ConsumeIntoWireTypeAndTagFailures) {
  for (const absl::string_view v :
       std::vector<absl::string_view>({"00", "f8ffffff1f", "f8ffffff7f"})) {
    SCOPED_TRACE(v);
    std::string bytes = HexDecodeOrDie(v);
    absl::string_view bytes_view = bytes;
    EXPECT_THAT(ConsumeIntoWireTypeAndTag(bytes_view), Not(IsOk()));
  }
}

TEST(ProtoParserTest,  SerializeIntoWireTypeAndTagSuccess) {
  for (const WireTypeAndTagCase& v : kWireTypeAndTagCases) {
    SCOPED_TRACE(v.hex_encoded_bytes);
    std::string buffer;
    buffer.resize(WireTypeAndTagLength(v.wiretype, v.tag));
    absl::Span<char> buffer_span = absl::MakeSpan(buffer);
    if (v.tag > 0 && v.tag < /* 2^29 = */ 536870912) {
      EXPECT_THAT(SerializeWireTypeAndTag(v.wiretype, v.tag, buffer_span),
                  IsOk());
      EXPECT_THAT(HexEncode(buffer), Eq(v.hex_encoded_bytes));
      EXPECT_THAT(buffer_span, IsEmpty());
    } else {
      EXPECT_THAT(SerializeWireTypeAndTag(v.wiretype, v.tag, buffer_span),
                  Not(IsOk()));
    }
  }
}

TEST(ConsumeBytesReturnStringView, ValidInput) {
  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  absl::string_view bytes_view = bytes;
  absl::StatusOr<absl::string_view> result =
      ConsumeBytesReturnStringView(bytes_view);
  ASSERT_THAT(result, IsOk());
  EXPECT_THAT(*result, Eq("1234567890"));
  EXPECT_THAT(bytes_view, Eq("XYZ"));
}


TEST(ConsumeBytesReturnStringView, EmptyString) {
  std::string bytes =
      absl::StrCat(/* 0 bytes */ HexDecodeOrDie("00"), "abcde");
  absl::string_view bytes_view = bytes;
  absl::StatusOr<absl::string_view> result =
      ConsumeBytesReturnStringView(bytes_view);
  ASSERT_THAT(result, IsOk());
  EXPECT_THAT(*result, Eq(""));
  EXPECT_THAT(bytes_view, Eq("abcde"));
}

TEST(ConsumeBytesReturnStringView, EmptyWithoutVarint) {
  absl::string_view bytes_view = "";
  ASSERT_THAT(ConsumeBytesReturnStringView(bytes_view), Not(IsOk()));
}

TEST(ConsumeBytesReturnStringView, InvalidVarint) {
  std::string bytes =
      absl::StrCat(/* 0 bytes */ HexDecodeOrDie("8000"), "abcde");
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(ConsumeBytesReturnStringView(bytes_view), Not(IsOk()));
}

TEST(ConsumeFixed32, Consumes4Bytes) {
  std::string bytes = "1234567";
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(ConsumeFixed32(bytes_view), IsOk());
  EXPECT_THAT(bytes_view, Eq("567"));
  ASSERT_THAT(ConsumeFixed32(bytes_view), Not(IsOk()));
}

TEST(ConsumeFixed64, Consumes8Bytes) {
  std::string bytes = "0abc4abc8abc2ab";
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(ConsumeFixed64(bytes_view), IsOk());
  EXPECT_THAT(bytes_view, Eq("8abc2ab"));
  ASSERT_THAT(ConsumeFixed64(bytes_view), Not(IsOk()));
}

TEST(SkipField, Fixed32) {
  std::string bytes = "1234567";
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipField(WireType::kFixed32, bytes_view), IsOk());
  EXPECT_THAT(bytes_view, Eq("567"));
  ASSERT_THAT(SkipField(WireType::kFixed32, bytes_view), Not(IsOk()));
}

TEST(SkipField, Fixed64) {
  std::string bytes = "0abc4abc8abc2ab";
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipField(WireType::kFixed64, bytes_view), IsOk());
  EXPECT_THAT(bytes_view, Eq("8abc2ab"));
  ASSERT_THAT(SkipField(WireType::kFixed64, bytes_view), Not(IsOk()));
}

TEST(SkipField, Varint) {
  std::string bytes = HexDecodeOrDie("08");
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipField(WireType::kVarint, bytes_view), IsOk());
  EXPECT_THAT(bytes_view, Eq(""));
  ASSERT_THAT(SkipField(WireType::kVarint, bytes_view), Not(IsOk()));
}

TEST(SkipField, VarintRemainder) {
  std::string bytes = HexDecodeOrDie("8808aa");
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipField(WireType::kVarint, bytes_view), IsOk());
  EXPECT_THAT(HexEncode(bytes_view), Eq("aa"));
}

TEST(SkipField, VarintFail) {
  std::string bytes = HexDecodeOrDie("888888");
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipField(WireType::kVarint, bytes_view), Not(IsOk()));
}

TEST(SkipField, LengthEncoded) {
  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipField(WireType::kLengthDelimited, bytes_view), IsOk());
  EXPECT_THAT(bytes_view, Eq("XYZ"));
}

TEST(SkipField, LengthEncodedTooShort) {
  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "123456789");
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipField(WireType::kLengthDelimited, bytes_view),
              Not(IsOk()));
}

TEST(SkipField, StartGroupFails) {
  std::string bytes = "some bytes";
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipField(WireType::kStartGroup, bytes_view),
              Not(IsOk()));
}
TEST(SkipField, EndGroupFalis) {
  std::string bytes = "some bytes";
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipField(WireType::kEndGroup, bytes_view),
              Not(IsOk()));
}

/* 3b: start group (field #7): 3 + 7 * 8 = 59 = 0x3b */
/* 3c:   end group (field #7): 4 + 7 * 8 = 60 = 0x3c */
/* 43: start group (field #8): 3 + 8 * 8 = 59 = 0x43 */
/* 44:   end group (field #8): 4 + 8 * 8 = 60 = 0x44 */
TEST(SkipGroup, BasicWorks) {
  std::string bytes = HexDecodeOrDie("3c");
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipGroup(7, bytes_view), IsOk());
  EXPECT_THAT(bytes_view, Eq(""));
}

TEST(SkipGroup, LeftOversAreKept) {
  std::string bytes = absl::StrCat(HexDecodeOrDie("3c"), "leftover");
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipGroup(7, bytes_view), IsOk());
  EXPECT_THAT(bytes_view, Eq("leftover"));
}

TEST(SkipGroup, WrongClosingTagFails) {
  std::string bytes = HexDecodeOrDie("44");
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipGroup(7, bytes_view), Not(IsOk()));
}

TEST(SkipGroup, NestedWorks) {
  std::string bytes = HexDecodeOrDie("433b3c443c");
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipGroup(7, bytes_view), IsOk());
  EXPECT_THAT(bytes_view, Eq(""));
}

TEST(SkipGroup, BadNestingFails) {
  std::string bytes = HexDecodeOrDie("433c44");
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipGroup(7, bytes_view), Not(IsOk()));
}

TEST(SkipGroup, NestedStringFieldWorks) {
  std::string bytes = HexDecodeOrDie(absl::StrCat(
      /* kLengthDelimited, tag#1 = */ "0a",
      /* 10 bytes length encoded */ "0a", "12345678901234567890", "3c"));
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipGroup(7, bytes_view), IsOk());
  EXPECT_THAT(bytes_view, Eq(""));
}

TEST(SkipGroup, NestedStringFieldTooShort) {
  std::string bytes = HexDecodeOrDie(absl::StrCat(
      /* kLengthDelimited, tag#1 = */ "0a",
      /* 10 bytes length encoded */ "0a", "1234567812345678", "3c"));
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipGroup(7, bytes_view), Not(IsOk()));
}

TEST(SkipGroup, NestedVarintFieldWorks) {
  std::string bytes = HexDecodeOrDie(absl::StrCat(
      /* kVarint, tag#1 = */ "08",
      /* Varint value 1 */ "08", "3c"));
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipGroup(7, bytes_view), IsOk());
  EXPECT_THAT(bytes_view, Eq(""));
}

TEST(SkipGroup, NestedFixed64FieldWorks) {
  std::string bytes = HexDecodeOrDie(absl::StrCat(
      /* kFixed64, tag#1 = */ "09",
      /* Varint value 1 */ "0011223344556677", "3c"));
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipGroup(7, bytes_view), IsOk());
  EXPECT_THAT(bytes_view, Eq(""));
}

TEST(SkipGroup, NestedFixed32FieldWorks) {
  std::string bytes = HexDecodeOrDie(absl::StrCat(
      /* kFixed32, tag#1 = */ "0d",
      /* Varint value 1 */ "00112233", "3c"));
  absl::string_view bytes_view = bytes;
  ASSERT_THAT(SkipGroup(7, bytes_view), IsOk());
  EXPECT_THAT(bytes_view, Eq(""));
}

}  // namespace

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
