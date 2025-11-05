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

#ifndef TINK_INTERNAL_PROTO_PARSER_PRESENCE_FIELDS_H_
#define TINK_INTERNAL_PROTO_PARSER_PRESENCE_FIELDS_H_

#include <cstddef>
#include <cstdint>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

class OptionalUint32Field final : public Field {
 public:
  explicit OptionalUint32Field(uint32_t field_number)
      : Field(field_number, WireType::kVarint) {}

  // Copyable and movable.
  OptionalUint32Field(const OptionalUint32Field&) = default;
  OptionalUint32Field& operator=(const OptionalUint32Field&) = default;
  OptionalUint32Field(OptionalUint32Field&&) noexcept = default;
  OptionalUint32Field& operator=(OptionalUint32Field&&) noexcept = default;

  void Clear() override { value_.reset(); }

  bool ConsumeIntoMember(ParsingState& serialized) override {
    absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(serialized);
    if (!result.ok()) {
      return false;
    }
    value_ = *result;
    return true;
  }

  absl::Status SerializeWithTagInto(SerializationState& out) const override {
    if (!value_.has_value()) {
      return absl::OkStatus();
    }
    absl::Status status =
        SerializeWireTypeAndFieldNumber(WireType::kVarint, FieldNumber(), out);
    if (!status.ok()) {
      return status;
    }
    return SerializeVarint(*value_, out);
  }

  size_t GetSerializedSizeIncludingTag() const override {
    if (!value_.has_value()) {
      return 0;
    }
    return WireTypeAndFieldNumberLength(WireType::kVarint, FieldNumber()) +
           VarintLength(*value_);
  }

  absl::optional<uint32_t> value() const { return value_; }
  void set_value(uint32_t value) { value_ = value; }

 private:
  absl::optional<uint32_t> value_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_PRESENCE_FIELDS_H_
