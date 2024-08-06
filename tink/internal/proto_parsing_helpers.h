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

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// Consumes (i.e. reads and removes from the input |serialized|) a Varint
// and returns it as a uint64_t.
absl::StatusOr<uint64_t> ConsumeVarintIntoUint64(absl::string_view& serialized);

// Consumes a Varint and returns it as a uint32_t.
absl::StatusOr<uint32_t> ConsumeVarintIntoUint32(absl::string_view& serialized);

int VarintLength(uint64_t value);
absl::Status SerializeVarint(uint64_t value, absl::Span<char>& output);

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

// Consumes a wiretype/tag encoding and returns the result.
absl::StatusOr<std::pair<WireType, int>> ConsumeIntoWireTypeAndTag(
    absl::string_view& serialized);

// Serializes a wiretype/tag into the output. Returns an error if the output
// buffer is too small or (!0 < tag < 2^29).
absl::Status SerializeWireTypeAndTag(WireType wire_type, int tag,
                                     absl::Span<char>& output);
int WireTypeAndTagLength(WireType wire_type, int tag);

// Consumes a length delimited field and returns the string_view to the field.
absl::StatusOr<absl::string_view> ConsumeBytesReturnStringView(
    absl::string_view& serialized);

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSING_HELPERS_H_
