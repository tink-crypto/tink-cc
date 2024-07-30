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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretDataFromStringView;
using ::crypto::tink::util::StatusOr;
using ::testing::Eq;
using ::testing::HasSubstr;
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
    // Note: proto only accepts tags up to 2^29-1, so this is the largest tag,
    // but our code currently accepts higher tags.
    {"f8ffffff1f", WireType::kVarint, 1073741823},
    // Note: overflow
    {"f8ffffff7f", WireType::kVarint, -1},
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

}  // namespace

}  // namespace internal
}  // namespace tink
}  // namespace crypto
