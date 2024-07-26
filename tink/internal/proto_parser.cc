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

#include "tink/internal/proto_parser.h"

#include <cstdint>
#include <limits>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/variant.h"

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
    serialized.remove_prefix(1);
    result |= ((byte & 0x7F) << (i * 7));
    if (!(byte & 0x80)) {
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

ProtoParser& ProtoParser::AddUint32Field(int tag, uint32_t& value) {
  if (!permanent_error_.ok()) {
    return *this;
  }
  Field field;
  field.type = ProtoFieldType::UINT32;
  field.value = &value;
  auto result = fields_.insert({tag, field});
  if (!result.second) {
    permanent_error_ = absl::InvalidArgumentError(
        absl::StrCat("Tag ", tag, " already exists"));
    return *this;
  }
  return *this;
}

absl::Status ProtoParser::Parse(absl::string_view input) {
  if (!permanent_error_.ok()) {
    return permanent_error_;
  }
  permanent_error_ = absl::FailedPreconditionError("Parse called twice");
  ClearAllFields();
  while (!input.empty()) {
    absl::StatusOr<std::pair<WireType, int>> wiretype_and_tag =
        ConsumeIntoWireTypeAndTag(input);
    if (!wiretype_and_tag.ok()) {
      return wiretype_and_tag.status();
    }
    if (wiretype_and_tag->first == WireType::kVarint) {
      absl::Status s = ConsumeVarintWithTag(input, wiretype_and_tag->second);
      if (!s.ok()) {
        return s;
      }
    } else {
      return absl::InvalidArgumentError(
          absl::StrCat("Unsupported wire type ", wiretype_and_tag->first));
    }
  }
  return absl::OkStatus();
}

absl::Status ProtoParser::ConsumeVarintWithTag(absl::string_view& serialized,
                                               int tag) {
  auto it = fields_.find(tag);
  if (it == fields_.end()) {
    return absl::InternalError(
        absl::StrCat("Tag ", tag, " not found in ConsumeVarintWithTag"));
  }
  if (it->second.type == ProtoFieldType::UINT32) {
    return ConsumeUint32WithField(serialized, it->second);
  }
  return absl::InvalidArgumentError(
      absl::StrCat("Tag ", tag, " of unknown type for Varint"));
}

absl::Status ProtoParser::ConsumeUint32WithField(
    absl::string_view& serialized, const ProtoParser::Field& field) {
  absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(serialized);
  if (!result.ok()) {
    return result.status();
  }
  *absl::get<uint32_t*>(field.value) = *result;
  return absl::OkStatus();
}

void ProtoParser::ClearAllFields() {
  for (auto& pair : fields_) {
    switch (pair.second.type) {
      case ProtoFieldType::UINT32:
        *absl::get<uint32_t*>(pair.second.value) = 0;
    }
  }
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
