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
#ifndef TINK_INTERNAL_PROTO_PARSER_OWNING_FIELDS_H_
#define TINK_INTERNAL_PROTO_PARSER_OWNING_FIELDS_H_

#include <cstddef>
#include <cstdint>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// Represents a proto filed that owns the underlying value.
class OwningField {
 public:
  explicit OwningField(uint32_t field_number, WireType wire_type)
      : field_number_(field_number), wire_type_(wire_type) {}
  virtual ~OwningField() = default;

  // Clears the field.
  virtual void Clear() = 0;

  // Consumes the serialized data and parses it into the field. Returns true if
  // the parsing was successful.
  virtual ABSL_MUST_USE_RESULT bool ConsumeIntoMember(
      ParsingState& serialized) = 0;

  // Serializes the field into the given serialization state. Returns true if
  // the serialization was successful.
  virtual absl::Status SerializeWithTagInto(SerializationState& out) const = 0;

  // Returns the size of the serialized field, including the tag.
  virtual size_t GetSerializedSizeIncludingTag() const = 0;

  WireType GetWireType() const { return wire_type_; }
  uint32_t FieldNumber() const { return field_number_; }

 private:
  const uint32_t field_number_;
  const WireType wire_type_;
};

class Uint32OwningField : public OwningField {
 public:
  explicit Uint32OwningField(
      uint32_t field_number,
      ProtoFieldOptions options = ProtoFieldOptions::kNone)
      : OwningField(field_number, WireType::kVarint),
        field_(field_number, &Uint32OwningField::value_, options) {}

  // Copyable and movable.
  Uint32OwningField(const Uint32OwningField&) = default;
  Uint32OwningField& operator=(const Uint32OwningField&) = default;
  Uint32OwningField(Uint32OwningField&&) noexcept = default;
  Uint32OwningField& operator=(Uint32OwningField&&) noexcept = default;

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

  void set_value(uint32_t value) { value_ = value; }
  uint32_t value() const { return value_; }

 private:
  uint32_t value_ = 0;
  Uint32Field<Uint32OwningField> field_;
};

template <typename StringLike>
class OwningBytesField final : public OwningField {
 public:
  explicit OwningBytesField(uint32_t field_number, ProtoFieldOptions options =
                                                       ProtoFieldOptions::kNone)
      : OwningField(field_number, WireType::kLengthDelimited),
        field_(field_number, &OwningBytesField<StringLike>::value_, options) {}
  // Copyable and movable.
  OwningBytesField(const OwningBytesField&) = default;
  OwningBytesField& operator=(const OwningBytesField&) = default;
  OwningBytesField(OwningBytesField&&) noexcept = default;
  OwningBytesField& operator=(OwningBytesField&&) noexcept = default;

  void Clear() override { ClearStringLikeValue(value_); }
  bool ConsumeIntoMember(ParsingState& serialized) override {
    return field_.ConsumeIntoMember(serialized, *this);
  }
  absl::Status SerializeWithTagInto(SerializationState& out) const override {
    return field_.SerializeWithTagInto(out, *this);
  }
  size_t GetSerializedSizeIncludingTag() const override {
    return field_.GetSerializedSizeIncludingTag(*this);
  }

  void set_value(absl::string_view value) {
    CopyIntoStringLikeValue(value, value_);
  }
  const StringLike& value() const { return value_; }
  StringLike* mutable_value() { return &value_; }

 private:
  StringLike value_;
  BytesField<OwningBytesField<StringLike>, StringLike> field_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_OWNING_FIELDS_H_
