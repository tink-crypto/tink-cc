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
#include "tink/internal/proto_parser_state.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

namespace {

constexpr int kMax64BitVarintLength = 10;
constexpr int kMax32BitVarintLength = 5;
constexpr int kSkipGroupLimit = 100;

// Consumes a varint for the case where it is used in a tag. The behavior of
// the proto library is subtly different in each case, and we currently want to
// follow it closely. In tags, we should restrict parsing to size 5 and handle
// overflows by taking mod 2^32.
absl::StatusOr<uint32_t> ConsumeVarintForTag(ParsingState& parsing_state) {
  uint32_t result = 0;
  for (int i = 0; i < kMax32BitVarintLength; ++i) {
    if (parsing_state.ParsingDone()) {
      return absl::InvalidArgumentError("Varint too short");
    }
    uint32_t byte = parsing_state.PeekByte();
    parsing_state.Advance(1);
    result |= ((byte & 0x7F) << (i * 7));
    if (!(byte & 0x80)) {
      return result;
    }
  }
  return absl::InvalidArgumentError("Varint too long");
}

// Consumes a varint for the case where it is used in a length delimited field.
// The behavior of the proto library is subtly different in each case, and we
// currently want to follow it closely. In size, we are very strict and do not
// allow additional bits set.
absl::StatusOr<uint32_t> ConsumeVarintForSize(ParsingState& parsing_state) {
  uint32_t result = 0;
  for (int i = 0; i < kMax32BitVarintLength; ++i) {
    if (parsing_state.ParsingDone()) {
      return absl::InvalidArgumentError("Varint too short");
    }
    uint32_t byte = parsing_state.PeekByte();
    if (i == kMax32BitVarintLength - 1) {
      if ((byte & 0x7F) > (std::numeric_limits<uint32_t>::max() >> (i * 7))) {
        return absl::InvalidArgumentError(
            "Length delimeted field declared to be longer than 2^32-1 bytes");
      }
    }
    parsing_state.Advance(1);
    result |= ((byte & 0x7F) << (i * 7));
    if (!(byte & 0x80)) {
      return result;
    }
  }
  return absl::InvalidArgumentError("Size varint encoded in more than 5 bytes");
}

}  // namespace

// See https://protobuf.dev/programming-guides/encoding for documentation on
// the wire format.

// https://protobuf.dev/programming-guides/encoding/#varints
absl::StatusOr<uint64_t> ConsumeVarintIntoUint64(ParsingState& parsing_state) {
  uint64_t result = 0;
  for (int i = 0; i < kMax64BitVarintLength; ++i) {
    if (parsing_state.ParsingDone()) {
      return absl::InvalidArgumentError("Varint too short");
    }
    uint64_t byte = parsing_state.PeekByte();
    parsing_state.Advance(1);
    result |= ((byte & 0x7F) << (i * 7));
    if (!(byte & 0x80)) {
      return result;
    }
  }
  return absl::InvalidArgumentError("Varint too long");
}

absl::StatusOr<uint32_t> ConsumeVarintIntoUint32(ParsingState& parsing_state) {
  absl::StatusOr<uint64_t> result = ConsumeVarintIntoUint64(parsing_state);
  if (!result.ok()) {
    return result.status();
  }
  // Writing static_cast<> isn't needed, but I want to make it explicit.
  return static_cast<uint32_t>(*result);
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
absl::StatusOr<std::pair<WireType, int>> ConsumeIntoWireTypeAndFieldNumber(
    ParsingState& parsing_state) {
  absl::StatusOr<uint32_t> result = ConsumeVarintForTag(parsing_state);
  if (!result.ok()) {
    return result.status();
  }
  int field_number = *result >> 3;
  WireType wiretype = static_cast<WireType>(*result & 0x7);
  if (field_number == 0) {
    return absl::InvalidArgumentError("Field number 0 disallowed");
  }
  return std::make_pair(wiretype, field_number);
}

absl::Status SerializeWireTypeAndFieldNumber(WireType wire_type,
                                             int field_number,
                                             absl::Span<char>& output) {
  if (field_number <= 0 || field_number >= (1<<29)) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Field Number ", field_number, " is not in range [1, 2^29)"));
  }
  uint32_t shifted = static_cast<uint32_t>(field_number) << 3;
  return SerializeVarint(shifted | static_cast<uint32_t>(wire_type),
                         output);
}

int WireTypeAndFieldNumberLength(WireType wire_type, int field_number) {
  // Result is wrong for negative field_number and field_number > 2^29, but the
  // caller will call SerializeWireTypeAndFieldNumber anyhow and notice there.
  int bit_width = absl::bit_width(static_cast<uint32_t>(field_number)) + 3;
  return (bit_width + 6) / 7;
}

absl::StatusOr<absl::string_view> ConsumeBytesReturnStringView(
    ParsingState& parsing_state) {
  absl::StatusOr<uint32_t> result = ConsumeVarintForSize(parsing_state);
  if (!result.ok()) {
    return result.status();
  }
  if (*result > parsing_state.RemainingData().size()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Length ", *result, " exceeds remaining input size ",
                     parsing_state.RemainingData()));
  }
  absl::string_view result_view =
      parsing_state.RemainingData().substr(0, *result);
  parsing_state.Advance(*result);
  return result_view;
}

absl::Status ConsumeFixed32(ParsingState& parsing_state) {
  if (parsing_state.RemainingData().size() < 4) {
    return absl::InvalidArgumentError("Not enough data to read kFixed32");
  }
  parsing_state.Advance(4);
  return absl::OkStatus();
}

absl::Status ConsumeFixed64(ParsingState& parsing_state) {
  if (parsing_state.RemainingData().size() < 8) {
    return absl::InvalidArgumentError("Not enough data to read kFixed64");
  }
  parsing_state.Advance(8);
  return absl::OkStatus();
}

absl::Status SkipField(WireType wire_type, ParsingState& parsing_state) {
  if (wire_type == WireType::kVarint) {
    return ConsumeVarintIntoUint64(parsing_state).status();
  }
  if (wire_type == WireType::kLengthDelimited) {
    return ConsumeBytesReturnStringView(parsing_state).status();
  }
  if (wire_type == WireType::kFixed32) {
    return ConsumeFixed32(parsing_state);
  }
  if (wire_type == WireType::kFixed64) {
    return ConsumeFixed64(parsing_state);
  }
  return absl::InvalidArgumentError(
      absl::StrCat("Cannot skip fields of wire type ", wire_type));
}

absl::Status SkipGroup(int field_number, ParsingState& parsing_state) {
  std::vector<int> field_number_stack;
  field_number_stack.push_back(field_number);

  while (!field_number_stack.empty()) {
    absl::StatusOr<std::pair<WireType, int>> wiretype_and_field_number =
        ConsumeIntoWireTypeAndFieldNumber(parsing_state);
    if (!wiretype_and_field_number.ok()) {
      return wiretype_and_field_number.status();
    }
    switch (wiretype_and_field_number->first) {
      case WireType::kStartGroup: {
        field_number_stack.push_back(wiretype_and_field_number->second);
        if (field_number_stack.size() > kSkipGroupLimit) {
          return absl::InvalidArgumentError("Too many SGROUP tags");
        }
        continue;
      }
      case WireType::kEndGroup: {
        int popped = field_number_stack.back();
        field_number_stack.pop_back();
        if (popped != wiretype_and_field_number->second) {
          return absl::InvalidArgumentError("Group tags did not match");
        }
        continue;
      }
      default: {
        absl::Status s =
            SkipField(wiretype_and_field_number->first, parsing_state);
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
