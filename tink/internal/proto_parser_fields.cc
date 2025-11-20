// Copyright 2025 Google LLC
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
#include "tink/internal/proto_parser_fields.h"

#include <cstddef>
#include <cstdint>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// Uint32Field.

void Uint32Field::Clear() { value_ = 0; }
bool Uint32Field::ConsumeIntoMember(ParsingState& serialized) {
  absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(serialized);
  if (!result.ok()) {
    return false;
  }
  value_ = *result;
  return true;
}
absl::Status Uint32Field::SerializeWithTagInto(SerializationState& out) const {
  if (!RequiresSerialization()) {
    return absl::OkStatus();
  }
  absl::Status status =
      SerializeWireTypeAndFieldNumber(GetWireType(), FieldNumber(), out);
  if (!status.ok()) {
    return status;
  }
  return SerializeVarint(value_, out);
}
size_t Uint32Field::GetSerializedSizeIncludingTag() const {
  if (!RequiresSerialization()) {
    return 0;
  }
  return WireTypeAndFieldNumberLength(GetWireType(), FieldNumber()) +
         VarintLength(value_);
}

// Uint64Field.

void Uint64Field::Clear() { value_ = 0; }
bool Uint64Field::ConsumeIntoMember(ParsingState& serialized) {
  absl::StatusOr<uint64_t> result = ConsumeVarintIntoUint64(serialized);
  if (!result.ok()) {
    return false;
  }
  value_ = *result;
  return true;
}
absl::Status Uint64Field::SerializeWithTagInto(SerializationState& out) const {
  if (value_ == 0) {
    return absl::OkStatus();
  }
  absl::Status status =
      SerializeWireTypeAndFieldNumber(GetWireType(), FieldNumber(), out);
  if (!status.ok()) {
    return status;
  }
  return SerializeVarint(value_, out);
}
size_t Uint64Field::GetSerializedSizeIncludingTag() const {
  if (value_ == 0) {
    return 0;
  }
  return WireTypeAndFieldNumberLength(GetWireType(), FieldNumber()) +
         VarintLength(value_);
}

// BytesField.

void BytesField::Clear() { value_.clear(); }
bool BytesField::ConsumeIntoMember(ParsingState& serialized) {
  absl::StatusOr<absl::string_view> result =
      ConsumeBytesReturnStringView(serialized);
  if (!result.ok()) {
    return false;
  }
  set_value(*result);
  return true;
}
absl::Status BytesField::SerializeWithTagInto(SerializationState& out) const {
  if (!RequiresSerialization()) {
    return absl::OkStatus();
  }

  if (absl::Status result =
          SerializeWireTypeAndFieldNumber(GetWireType(), FieldNumber(), out);
      !result.ok()) {
    return result;
  }
  size_t size = value_.size();
  if (absl::Status result = SerializeVarint(size, out); !result.ok()) {
    return result;
  }
  if (out.GetBuffer().size() < size) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Output buffer too small: ", out.GetBuffer().size(), " < ", size));
  }
  // size is guaranteed to be <= out.GetBuffer().size().
  value_.copy(out.GetBuffer().data(), size);
  out.Advance(size);
  return absl::OkStatus();
}

size_t BytesField::GetSerializedSizeIncludingTag() const {
  if (!RequiresSerialization()) {
    return 0;
  }
  size_t size = value_.size();
  return WireTypeAndFieldNumberLength(GetWireType(), FieldNumber()) +
         VarintLength(size) + size;
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
