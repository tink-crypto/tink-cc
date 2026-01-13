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

#include <cstddef>
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
bool ConsumeVarintForTag(ParsingState& parsing_state, uint32_t& result) {
  result = 0;
  for (int i = 0; i < kMax32BitVarintLength; ++i) {
    if (parsing_state.ParsingDone()) {
      return false;
    }
    uint32_t byte = parsing_state.PeekByte();
    parsing_state.Advance(1);
    result |= ((byte & 0x7F) << (i * 7));
    if (!(byte & 0x80)) {
      return true;
    }
  }
  return false;
}

}  // namespace

// Consumes a varint for the case where it is used in a length delimited field.
// The behavior of the proto library is subtly different in each case, and we
// currently want to follow it closely. In size, we are very strict and do not
// allow additional bits set.
bool ConsumeVarintForSize(ParsingState& parsing_state, uint32_t& result) {
  result = 0;
  for (int i = 0; i < kMax32BitVarintLength; ++i) {
    if (parsing_state.ParsingDone()) {
      return false;
    }
    uint32_t byte = parsing_state.PeekByte();
    if (i == kMax32BitVarintLength - 1) {
      if ((byte & 0x7F) > (std::numeric_limits<uint32_t>::max() >> (i * 7))) {
        return false;
      }
    }
    parsing_state.Advance(1);
    result |= ((byte & 0x7F) << (i * 7));
    if (!(byte & 0x80)) {
      return true;
    }
  }
  return false;
}

// See https://protobuf.dev/programming-guides/encoding for documentation on
// the wire format.

// https://protobuf.dev/programming-guides/encoding/#varints
bool ConsumeVarintIntoUint64(ParsingState& parsing_state, uint64_t& result) {
  result = 0;
  for (int i = 0; i < kMax64BitVarintLength; ++i) {
    if (parsing_state.ParsingDone()) {
      return false;
    }
    uint64_t byte = parsing_state.PeekByte();
    parsing_state.Advance(1);
    result |= ((byte & 0x7F) << (i * 7));
    if (!(byte & 0x80)) {
      return true;
    }
  }
  return false;
}

bool ConsumeVarintIntoUint32(ParsingState& parsing_state, uint32_t& result) {
  uint64_t result64bit;
  if (!ConsumeVarintIntoUint64(parsing_state, result64bit)) {
    return false;
  }
  // Writing static_cast<> isn't needed, but I want to make it explicit.
  result = static_cast<uint32_t>(result64bit);
  return true;
}

int VarintLength(uint64_t value) {
  int bit_width = absl::bit_width(value);
  if (bit_width == 0) {
    return 1;
  }

  return (bit_width + 6) / 7;
}

bool SerializeVarint(uint64_t value, SerializationState& output) {
  size_t size = static_cast<size_t>(VarintLength(value));
  if (output.GetBuffer().size() < size) {
    return false;
  }
  absl::Span<char> output_buffer = output.GetBuffer();
  int i = 0;
  while (value >= 0x80) {
    output_buffer[i++] = (static_cast<char>(value) & 0x7f) | 0x80;
    value >>= 7;
  }
  output_buffer[i++] = static_cast<char>(value);
  output.Advance(size);
  return true;
}

// https://protobuf.dev/programming-guides/encoding/#structure
bool ConsumeIntoWireTypeAndFieldNumber(ParsingState& parsing_state,
                                       WireType& wire_type, int& field_number) {
  uint32_t result;
  if (!ConsumeVarintForTag(parsing_state, result)) {
    return false;
  }
  field_number = result >> 3;
  wire_type = static_cast<WireType>(result & 0x7);
  if (field_number == 0) {
    return false;
  }
  return true;
}

bool SerializeWireTypeAndFieldNumber(WireType wire_type, int field_number,
                                     SerializationState& output) {
  if (field_number <= 0 || field_number >= (1<<29)) {
    return false;
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

bool ConsumeBytesReturnStringView(ParsingState& parsing_state,
                                  absl::string_view& result_view) {
  uint32_t result;
  if (!ConsumeVarintForSize(parsing_state, result)) {
    return false;
  }
  if (result > parsing_state.RemainingData().size()) {
    return false;
  }
  result_view = parsing_state.RemainingData().substr(0, result);
  parsing_state.Advance(result);
  return true;
}

bool ConsumeFixed32(ParsingState& parsing_state) {
  if (parsing_state.RemainingData().size() < 4) {
    return false;
  }
  parsing_state.Advance(4);
  return true;
}

bool ConsumeFixed64(ParsingState& parsing_state) {
  if (parsing_state.RemainingData().size() < 8) {
    return false;
  }
  parsing_state.Advance(8);
  return true;
}

bool SkipField(WireType wire_type, ParsingState& parsing_state) {
  if (wire_type == WireType::kVarint) {
    uint64_t ignored;
    return ConsumeVarintIntoUint64(parsing_state, ignored);
  }
  if (wire_type == WireType::kLengthDelimited) {
    absl::string_view ignored;
    return ConsumeBytesReturnStringView(parsing_state, ignored);
  }
  if (wire_type == WireType::kFixed32) {
    return ConsumeFixed32(parsing_state);
  }
  if (wire_type == WireType::kFixed64) {
    return ConsumeFixed64(parsing_state);
  }
  return false;
}

bool SkipGroup(int field_number, ParsingState& parsing_state) {
  std::vector<int> field_number_stack;
  field_number_stack.push_back(field_number);

  while (!field_number_stack.empty()) {
    WireType wire_type;
    int field_number;
    if (!ConsumeIntoWireTypeAndFieldNumber(parsing_state, wire_type,
                                           field_number)) {
      return false;
    }
    switch (wire_type) {
      case WireType::kStartGroup: {
        field_number_stack.push_back(field_number);
        if (field_number_stack.size() > kSkipGroupLimit) {
          return false;
        }
        continue;
      }
      case WireType::kEndGroup: {
        int popped = field_number_stack.back();
        field_number_stack.pop_back();
        if (popped != field_number) {
          return false;
        }
        continue;
      }
      default: {
        if (!SkipField(wire_type, parsing_state)) {
          return false;
        }
      }
    }
  }
  return true;
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
