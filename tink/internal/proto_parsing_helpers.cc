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
#include <utility>
#include <vector>

#include "absl/numeric/bits.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

namespace {

constexpr int kMax64BitVarintLength = 10;
constexpr int kMax32BitVarintLength = 5;

// Consumes a varint for the case where it is used in a tag. The behavior of
// the proto library is subtly different in each case, and we currently want to
// follow it closely. In tags, we should restrict parsing to size 5 and handle
// overflows by taking mod 2^32.
absl::StatusOr<uint32_t> ConsumeVarintForTag(absl::string_view& serialized) {
  uint32_t result = 0;
  for (int i = 0; i < kMax32BitVarintLength; ++i) {
    if (serialized.empty()) {
      return absl::InvalidArgumentError("Varint too short");
    }
    uint32_t byte = *serialized.begin();
    serialized.remove_prefix(1);
    result |= ((byte & 0x7F) << (i * 7));
    if (!(byte & 0x80)) {
      return result;
    }
  }
  return absl::InvalidArgumentError("Varint too long");
}

}  // namespace

// See https://protobuf.dev/programming-guides/encoding for documentation on
// the wire format.

// https://protobuf.dev/programming-guides/encoding/#varints
absl::StatusOr<uint64_t> ConsumeVarintIntoUint64(
    absl::string_view& serialized) {
  uint64_t result = 0;
  for (int i = 0; i < kMax64BitVarintLength; ++i) {
    if (serialized.empty()) {
      return absl::InvalidArgumentError("Varint too short");
    }
    uint64_t byte = *serialized.begin();
    if (i == kMax64BitVarintLength - 1 && (byte & 0xfe)) {
      return absl::InvalidArgumentError(
          "Varint bigger than numeric_limit<uint64_t>::max()");
    }
    serialized.remove_prefix(1);
    result |= ((byte & 0x7F) << (i * 7));
    if (!(byte & 0x80)) {
      if (byte == 0 && i != 0) {
        return absl::InvalidArgumentError(
            "Varint not in canoncial encoding (ends with 0)");
      }
      return result;
    }
  }
  return absl::InvalidArgumentError("Varint too long");
}

absl::StatusOr<uint32_t> ConsumeVarintIntoUint32(
    absl::string_view& serialized) {
  absl::StatusOr<uint64_t> result = ConsumeVarintIntoUint64(serialized);
  if (!result.ok()) {
    return result.status();
  }
  if (*result > std::numeric_limits<uint32_t>::max()) {
    return absl::InvalidArgumentError(
        "Parsed value too large to fit in uint32_t");
  }
  return *result;
}

int VarintLength(uint64_t value) {
  int bit_width = absl::bit_width(value);
  if (bit_width == 0) {
    return 1;
  }

  return (bit_width + 6) / 7;
}

absl::Status SerializeVarint(uint64_t value, absl::Span<char>& output) {
  int size = VarintLength(value);
  if (output.size() < size) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Output buffer too small to contain varint of size ", size));
  }
  for (int i = 0; i < size; ++i) {
    uint64_t byte = (value >> (7 * i)) & 0x7f;
    if (i != size - 1) {
      byte |= 0x80;
    }
    output[i] = byte;
  }
  output.remove_prefix(size);
  return absl::OkStatus();
}

// https://protobuf.dev/programming-guides/encoding/#structure
absl::StatusOr<std::pair<WireType, int>> ConsumeIntoWireTypeAndTag(
    absl::string_view& serialized) {
  absl::StatusOr<uint32_t> result = ConsumeVarintForTag(serialized);
  if (!result.ok()) {
    return result.status();
  }
  int tag = *result >> 3;
  WireType wiretype = static_cast<WireType>(*result & 0x7);
  if (tag == 0) {
    return absl::InvalidArgumentError("Field number 0 disallowed");
  }
  return std::make_pair(wiretype, tag);
}

absl::Status SerializeWireTypeAndTag(WireType wire_type, int tag,
                                     absl::Span<char>& output) {
  if (tag <= 0 || tag >= (1<<29)) {
    return absl::InvalidArgumentError(
        absl::StrCat("Tag ", tag, " is not in range [1, 2^29)"));
  }
  uint32_t shifted_tag = static_cast<uint32_t>(tag) << 3;
  return SerializeVarint(shifted_tag | static_cast<uint32_t>(wire_type),
                         output);
}

int WireTypeAndTagLength(WireType wire_type, int tag) {
  // Result is wrong for negative tags and numbers > 2^29, but the caller will
  // call SerializeWireTypeAndTag anyhow and notice there.
  int bit_width = absl::bit_width(static_cast<uint32_t>(tag)) + 3;
  return (bit_width + 6) / 7;
}

absl::StatusOr<absl::string_view> ConsumeBytesReturnStringView(
    absl::string_view& serialized) {
  absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(serialized);
  if (!result.ok()) {
    return result.status();
  }
  if (*result > serialized.size()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Length ", *result, " exceeds remaining input size ",
                     serialized.size()));
  }
  absl::string_view result_view = serialized.substr(0, *result);
  serialized.remove_prefix(*result);
  return result_view;
}

absl::Status ConsumeFixed32(absl::string_view& serialized) {
  if (serialized.size() < 4) {
    return absl::InvalidArgumentError("Not enough data to read kFixed32");
  }
  serialized.remove_prefix(4);
  return absl::OkStatus();
}

absl::Status ConsumeFixed64(absl::string_view& serialized) {
  if (serialized.size() < 8) {
    return absl::InvalidArgumentError("Not enough data to read kFixed64");
  }
  serialized.remove_prefix(8);
  return absl::OkStatus();
}

absl::Status SkipField(WireType wire_type, absl::string_view& serialized) {
  if (wire_type == WireType::kVarint) {
    return ConsumeVarintIntoUint64(serialized).status();
  }
  if (wire_type == WireType::kLengthDelimited) {
    return ConsumeBytesReturnStringView(serialized).status();
  }
  if (wire_type == WireType::kFixed32) {
    return ConsumeFixed32(serialized);
  }
  if (wire_type == WireType::kFixed64) {
    return ConsumeFixed64(serialized);
  }
  return absl::InvalidArgumentError(
      absl::StrCat("Cannot skip fields of wire type ", wire_type));
}

absl::Status SkipGroup(int field_number, absl::string_view& serialized) {
  std::vector<int> field_number_stack;
  field_number_stack.push_back(field_number);

  while (!field_number_stack.empty()) {
    absl::StatusOr<std::pair<WireType, int>> wiretype_and_tag =
        ConsumeIntoWireTypeAndTag(serialized);
    if (!wiretype_and_tag.ok()) {
      return wiretype_and_tag.status();
    }
    switch (wiretype_and_tag->first) {
      case WireType::kStartGroup: {
        field_number_stack.push_back(wiretype_and_tag->second);
        continue;
      }
      case WireType::kEndGroup: {
        int popped = field_number_stack.back();
        field_number_stack.pop_back();
        if (popped != wiretype_and_tag->second) {
          return absl::InvalidArgumentError("Group tags did not match");
        }
        continue;
      }
      default: {
        absl::Status s = SkipField(wiretype_and_tag->first, serialized);
        if (!s.ok()) {
          return s;
        }
      }
    }
  }
  return absl::OkStatus();
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
