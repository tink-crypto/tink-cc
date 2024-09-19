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

#ifndef TINK_INTERNAL_PROTO_PARSING_HELPERS_H_
#define TINK_INTERNAL_PROTO_PARSING_HELPERS_H_

#include <cstdint>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_state.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// Consumes (i.e. reads and removes from the input |parsing_state|) a Varint
// and returns it as a uint64_t.
absl::StatusOr<uint64_t> ConsumeVarintIntoUint64(ParsingState& parsing_state);

// Consumes a Varint and returns it as a uint32_t.
absl::StatusOr<uint32_t> ConsumeVarintIntoUint32(ParsingState& parsing_state);

int VarintLength(uint64_t value);
absl::Status SerializeVarint(uint64_t value, SerializationState& output);

// See https://protobuf.dev/programming-guides/encoding/#structure
// and
// https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/wire_format_lite.h
// for the names.
enum class WireType : uint8_t {
  kVarint = 0,
  kFixed64 = 1,
  kLengthDelimited = 2,
  kStartGroup = 3,
  kEndGroup = 4,
  kFixed32 = 5,
};

// Consumes a wiretype/field number encoding and returns the result.
absl::StatusOr<std::pair<WireType, int>> ConsumeIntoWireTypeAndFieldNumber(
    ParsingState& parsing_state);

// Serializes a wiretype/field_number into the output. Returns an error if the
// output buffer is too small or field_number is not in the range [1, 2^29-1].
absl::Status SerializeWireTypeAndFieldNumber(WireType wire_type,
                                             int field_number,
                                             SerializationState& output);
int WireTypeAndFieldNumberLength(WireType wire_type, int field_number);

// Consumes a length delimited field and returns the string_view to the field.
absl::StatusOr<absl::string_view> ConsumeBytesReturnStringView(
    ParsingState& parsing_state);

// Consumes a Fixed32 byte field. Currently returns Status instead of
// StatusOr<uint32_t> as we never need the value.
absl::Status ConsumeFixed32(ParsingState& parsing_state);
// Consumes a Fixed64 byte field. Currently returns Status instead of
// StatusOr<uint64_t> as we never need the value.
absl::Status ConsumeFixed64(ParsingState& parsing_state);

// Skips a field of type "wire_type". Returns non-ok status for
// wire_type == kStartGroup/kEndGroup, or if too little data in parsing_state.
// Note: kStartGroup needs to be skipped with SkipGroup.
absl::Status SkipField(WireType wire_type, ParsingState& parsing_state);

// Skips a field of type "kStartGroup". This is a separate method because it
// needs to be called differently and we want to ensure that there is no
// recursion to limit stack growth (so SkipField should never call SkipGroup).
absl::Status SkipGroup(int field_number, ParsingState& parsing_state);

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSING_HELPERS_H_
