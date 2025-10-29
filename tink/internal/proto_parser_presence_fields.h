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
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

template <typename Struct>
class Uint32FieldWithPresence : public Field<Struct> {
 public:
  explicit Uint32FieldWithPresence(int field_number,
                                   absl::optional<uint32_t> Struct::*value)
      : value_(value), field_number_(field_number) {}

  // Not copyable, not movable.
  Uint32FieldWithPresence(const Uint32FieldWithPresence&) = delete;
  Uint32FieldWithPresence& operator=(const Uint32FieldWithPresence&) = delete;
  Uint32FieldWithPresence(Uint32FieldWithPresence&&) noexcept = delete;
  Uint32FieldWithPresence& operator=(Uint32FieldWithPresence&&) noexcept =
      delete;

  void ClearMember(Struct& s) const override { (s.*value_).reset(); }

  bool ConsumeIntoMember(ParsingState& serialized, Struct& s) const override {
    absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(serialized);
    if (!result.ok()) {
      return false;
    }
    s.*value_ = *result;
    return true;
  }

  WireType GetWireType() const override { return WireType::kVarint; }
  int GetFieldNumber() const override { return field_number_; }

  absl::Status SerializeWithTagInto(SerializationState& out,
                             const Struct& values) const override {
    if (!RequiresSerialization(values)) {
      return absl::OkStatus();
    }
    absl::Status status =
        SerializeWireTypeAndFieldNumber(GetWireType(), GetFieldNumber(), out);
    if (!status.ok()) {
      return status;
    }
    if (!(values.*value_).has_value()) {
      return absl::InvalidArgumentError(
          "Must not call SerializeInto on absent Uint32FieldWithPresence");
    }
    return SerializeVarint(*(values.*value_), out);
  }

  size_t GetSerializedSizeIncludingTag(const Struct& values) const override {
    if (!RequiresSerialization(values)) {
      return 0;
    }
    if (!(values.*value_).has_value()) {
      // We should never get here.
      return 0;
    }
    return WireTypeAndFieldNumberLength(GetWireType(), GetFieldNumber()) +
           VarintLength(*(values.*value_));
  }

 private:
  bool RequiresSerialization(const Struct& values) const {
    return (values.*value_).has_value();
  }

  absl::optional<uint32_t> Struct::*value_;
  int field_number_;
};

class OptionalUint32Field final : public OwningField {
 public:
  explicit OptionalUint32Field(uint32_t field_number)
      : OwningField(field_number, WireType::kVarint),
        field_(field_number, &OptionalUint32Field::value_) {}
  // Copyable and movable.
  OptionalUint32Field(const OptionalUint32Field&) = default;
  OptionalUint32Field& operator=(const OptionalUint32Field&) = default;
  OptionalUint32Field(OptionalUint32Field&&) noexcept = default;
  OptionalUint32Field& operator=(OptionalUint32Field&&) noexcept = default;

  void Clear() override { field_.ClearMember(*this); }
  bool ConsumeIntoMember(ParsingState& serialized) override {
    return field_.ConsumeIntoMember(serialized, *this);
  }
  absl::Status SerializeWithTagInto(SerializationState& out) const override {
    return field_.SerializeWithTagInto(out, *this);
  }
  size_t GetSerializedSizeIncludingTag() const override {
    return field_.GetSerializedSizeIncludingTag(*this);
  }

  absl::optional<uint32_t> value() const { return value_; }
  void set_value(uint32_t value) { value_ = value; }

 private:
  absl::optional<uint32_t> value_;
  Uint32FieldWithPresence<OptionalUint32Field> field_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_PRESENCE_FIELDS_H_
