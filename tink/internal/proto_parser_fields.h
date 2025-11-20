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
#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// Represents a proto filed that owns the underlying value.
class Field {
 public:
  explicit Field(uint32_t field_number, WireType wire_type)
      : field_number_(field_number), wire_type_(wire_type) {}
  virtual ~Field() = default;

  // Copyable and movable.
  Field(const Field&) = default;
  Field& operator=(const Field&) = default;
  Field(Field&&) noexcept = default;
  Field& operator=(Field&&) noexcept = default;

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
  uint32_t field_number_;
  WireType wire_type_;
};

class Uint32Field : public Field {
 public:
  explicit Uint32Field(uint32_t field_number,
                       ProtoFieldOptions options = ProtoFieldOptions::kNone)
      : Field(field_number, WireType::kVarint), options_(options) {}

  // Copyable and movable.
  Uint32Field(const Uint32Field&) = default;
  Uint32Field& operator=(const Uint32Field&) = default;
  Uint32Field(Uint32Field&&) noexcept = default;
  Uint32Field& operator=(Uint32Field&&) noexcept = default;

  void Clear() override;
  bool ConsumeIntoMember(ParsingState& serialized) override;
  absl::Status SerializeWithTagInto(SerializationState& out) const override;
  size_t GetSerializedSizeIncludingTag() const override;

  void set_value(uint32_t value) { value_ = value; }
  uint32_t value() const { return value_; }

 private:
  bool RequiresSerialization() const {
    return options_ == ProtoFieldOptions::kAlwaysPresent || value_ != 0;
  }

  uint32_t value_ = 0;
  ProtoFieldOptions options_;
};

class Uint64Field : public Field {
 public:
  explicit Uint64Field(uint64_t field_number)
      : Field(field_number, WireType::kVarint) {}

  // Copyable and movable.
  Uint64Field(const Uint64Field&) = default;
  Uint64Field& operator=(const Uint64Field&) = default;
  Uint64Field(Uint64Field&&) noexcept = default;
  Uint64Field& operator=(Uint64Field&&) noexcept = default;

  void Clear() override;
  bool ConsumeIntoMember(ParsingState& serialized) override;
  absl::Status SerializeWithTagInto(SerializationState& out) const override;
  size_t GetSerializedSizeIncludingTag() const override;

  void set_value(uint64_t value) { value_ = value; }
  uint64_t value() const { return value_; }

 private:
  uint64_t value_ = 0;
};

class BytesField final : public Field {
 public:
  explicit BytesField(uint32_t field_number,
                      ProtoFieldOptions options = ProtoFieldOptions::kNone)
      : Field(field_number, WireType::kLengthDelimited), options_(options) {}
  // Copyable and movable.
  BytesField(const BytesField&) = default;
  BytesField& operator=(const BytesField&) = default;
  BytesField(BytesField&&) noexcept = default;
  BytesField& operator=(BytesField&&) noexcept = default;

  void Clear() override;
  bool ConsumeIntoMember(ParsingState& serialized) override;
  absl::Status SerializeWithTagInto(SerializationState& out) const override;
  size_t GetSerializedSizeIncludingTag() const override;

  void set_value(absl::string_view value) { value_ = std::string(value); }
  const std::string& value() const { return value_; }
  std::string* mutable_value() { return &value_; }

 private:
  bool RequiresSerialization() const {
    return options_ == ProtoFieldOptions::kAlwaysPresent || !value_.empty();
  }

  std::string value_;
  ProtoFieldOptions options_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_OWNING_FIELDS_H_
