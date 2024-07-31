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

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {
constexpr int kMaxVarintLength = 10;
}

// See https://protobuf.dev/programming-guides/encoding for documentation on
// the wire format.

// https://protobuf.dev/programming-guides/encoding/#varints
absl::StatusOr<uint64_t> ConsumeVarintIntoUint64(
    absl::string_view& serialized) {
  uint64_t result = 0;
  for (int i = 0; i < kMaxVarintLength; ++i) {
    if (serialized.empty()) {
      return absl::InvalidArgumentError("Varint too short");
    }
    uint64_t byte = *serialized.begin();
    if (i == kMaxVarintLength - 1 && (byte & 0xfe)) {
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

// https://protobuf.dev/programming-guides/encoding/#structure
absl::StatusOr<std::pair<WireType, int>> ConsumeIntoWireTypeAndTag(
    absl::string_view& serialized) {
  absl::StatusOr<uint64_t> result = ConsumeVarintIntoUint64(serialized);
  if (!result.ok()) {
    return result.status();
  }
  int tag = *result >> 3;
  WireType wiretype = static_cast<WireType>(*result & 0x7);
  return std::make_pair(wiretype, tag);
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

}  // namespace internal
}  // namespace tink
}  // namespace crypto
