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

#ifndef TINK_INTERNAL_PROTO_PARSER_ENUM_FIELD_H_
#define TINK_INTERNAL_PROTO_PARSER_ENUM_FIELD_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <type_traits>
#include <utility>

#include "absl/log/check.h"
#include "absl/status/status.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

template <typename Struct, typename Enum>
class EnumField : public Field<Struct> {
 public:
  explicit EnumField(int field_number, Enum Struct::* value,
                     std::function<bool(uint32_t)> is_valid,
                     Enum default_value = {},
                     ProtoFieldOptions options = ProtoFieldOptions::kNone)
      : field_number_(field_number),
        value_(value),
        is_valid_(std::move(is_valid)),
        default_value_(default_value),
        options_(options) {
    static_assert(std::numeric_limits<std::underlying_type_t<Enum>>::max() <=
                      std::numeric_limits<uint32_t>::max(),
                  "Only sizes up to uint32_t are supported as underlying type");
  }

  // Copyable and movable.
  EnumField(const EnumField&) = default;
  EnumField& operator=(const EnumField&) = default;
  EnumField(EnumField&&) noexcept = default;
  EnumField& operator=(EnumField&&) noexcept = default;

  void ClearMember(Struct& s) const override { s.*value_ = default_value_; }

  bool ConsumeIntoMember(ParsingState& serialized, Struct& s) const override {
    absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(serialized);
    if (!result.ok()) {
      return false;
    }
    if (!is_valid_(result.value())) {
      return true;
    }
    s.*value_ = static_cast<Enum>(*result);
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
    return SerializeVarint(static_cast<uint32_t>(values.*value_), out);
  }

  size_t GetSerializedSizeIncludingTag(const Struct& values) const override {
    if (!RequiresSerialization(values)) {
      return 0;
    }
    return WireTypeAndFieldNumberLength(GetWireType(), GetFieldNumber()) +
           VarintLength(static_cast<uint32_t>(values.*value_));
  }

 private:
  bool RequiresSerialization(const Struct& values) const {
    return (options_ == ProtoFieldOptions::kAlwaysSerialize) ||
           values.*value_ != default_value_;
  }

  int field_number_;
  Enum Struct::* value_;
  std::function<bool(uint32_t)> is_valid_;
  Enum default_value_;
  ProtoFieldOptions options_;
};

template <typename Enum>
class EnumOwningField : public OwningField {
 public:
  explicit EnumOwningField(int field_number,
                           std::function<bool(uint32_t)> is_valid,
                           Enum default_value = {},
                           ProtoFieldOptions options = ProtoFieldOptions::kNone)
      : OwningField(field_number, WireType::kVarint),
        value_(default_value),
        field_(field_number, &EnumOwningField::value_, std::move(is_valid),
               default_value, options) {}

  // Copyable and movable.
  EnumOwningField(const EnumOwningField&) = default;
  EnumOwningField& operator=(const EnumOwningField&) = default;
  EnumOwningField(EnumOwningField&&) noexcept = default;
  EnumOwningField& operator=(EnumOwningField&&) noexcept = default;

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

  const Enum& value() const { return value_; }
  void set_value(Enum value) { value_ = value; }

 private:
  Enum value_;
  EnumField<EnumOwningField, Enum> field_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_ENUM_FIELD_H_
