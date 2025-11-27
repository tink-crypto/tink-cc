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
#include <optional>
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
  virtual ABSL_MUST_USE_RESULT bool SerializeWithTagInto(
      SerializationState& out) const = 0;

  // Returns the size of the serialized field, including the tag.
  virtual size_t GetSerializedSizeIncludingTag() const = 0;

  WireType GetWireType() const { return wire_type_; }
  uint32_t FieldNumber() const { return field_number_; }

 private:
  uint32_t field_number_;
  WireType wire_type_;
};

// Represents a proto field that owns a uint32_t.
//
// Note:
// * if options == ProtoFieldOptions::kAlwaysPresent, then the field is
//   always present (i.e., has_value() never returns false). This forces
//   serialization as well, which is useful if the field is LEGACY_REQUIRED in
//   proto.
// * if options == ProtoFieldOptions::kExplicit, then the field is serialized
//   only if the value is set (even if with a default value).
// * if options == ProtoFieldOptions::kImplicit, then has_value() always returns
//   true; the field is serialized only if not equal to the default value (0).
//   (Note: Message implementations with kImplicit fields should not
//   expose `has_*` methods for compatibility with Protobufs.)
//
// This class is not thread-safe.
class Uint32Field : public Field {
 public:
  explicit Uint32Field(uint32_t field_number, ProtoFieldOptions options =
                                                  ProtoFieldOptions::kExplicit);

  // Copyable and movable.
  Uint32Field(const Uint32Field&) = default;
  Uint32Field& operator=(const Uint32Field&) = default;
  Uint32Field(Uint32Field&&) noexcept = default;
  Uint32Field& operator=(Uint32Field&&) noexcept = default;

  void Clear() override;
  bool ConsumeIntoMember(ParsingState& serialized) override;
  bool SerializeWithTagInto(SerializationState& out) const override;
  size_t GetSerializedSizeIncludingTag() const override;

  bool has_value() const { return value_.has_value(); }
  void set_value(uint32_t value) { value_ = value; }
  uint32_t value() const { return value_.value_or(0); }

 private:
  bool RequiresSerialization() const;

  std::optional<uint32_t> value_ = 0;
  ProtoFieldOptions options_;
};

// Represents a proto field that owns a uint64_t.
//
// Note:
// * if options == ProtoFieldOptions::kAlwaysPresent, then the field is
//   always present (i.e., has_value() never returns false). This forces
//   serialization as well, which is useful if the field is LEGACY_REQUIRED in
//   proto.
// * if options == ProtoFieldOptions::kExplicit, then the field is serialized
//   only if the value is set (even if with a default value).
// * if options == ProtoFieldOptions::kImplicit, then has_value() always returns
//   true; the field is serialized only if not equal to the default value (0).
//   (Note: Message implementations with kImplicit fields should not
//   expose `has_*` methods for compatibility with Protobufs.)
//
// This class is not thread-safe.
class Uint64Field : public Field {
 public:
  explicit Uint64Field(uint64_t field_number, ProtoFieldOptions options =
                                                  ProtoFieldOptions::kExplicit);

  // Copyable and movable.
  Uint64Field(const Uint64Field&) = default;
  Uint64Field& operator=(const Uint64Field&) = default;
  Uint64Field(Uint64Field&&) noexcept = default;
  Uint64Field& operator=(Uint64Field&&) noexcept = default;

  void Clear() override;
  bool ConsumeIntoMember(ParsingState& serialized) override;
  bool SerializeWithTagInto(SerializationState& out) const override;
  size_t GetSerializedSizeIncludingTag() const override;

  bool has_value() const { return value_.has_value(); }
  void set_value(uint64_t value) { value_ = value; }
  uint64_t value() const { return value_.value_or(0); }

 private:
  bool RequiresSerialization() const;

  std::optional<uint64_t> value_ = 0;
  ProtoFieldOptions options_;
};

// Represents a proto field that owns a string.
//
// Note:
// * if options == ProtoFieldOptions::kAlwaysPresent, then the field is
//   always present (i.e., has_value() never returns false). This forces
//   serialization as well, which is useful if the field is LEGACY_REQUIRED in
//   proto.
// * if options == ProtoFieldOptions::kExplicit, then the field is serialized
//   only if the value is set (even if with a default value).
// * if options == ProtoFieldOptions::kImplicit, then has_value() always returns
//   true; the field is serialized only if not equal to the default value (empty
//   string).
//   (Note: Message implementations with kImplicit fields should not
//   expose `has_*` methods for compatibility with Protobufs.)
//
// This class is not thread-safe.
class BytesField final : public Field {
 public:
  explicit BytesField(uint32_t field_number,
                      ProtoFieldOptions options = ProtoFieldOptions::kExplicit);
  // Copyable and movable.
  BytesField(const BytesField&) = default;
  BytesField& operator=(const BytesField&) = default;
  BytesField(BytesField&&) noexcept = default;
  BytesField& operator=(BytesField&&) noexcept = default;

  void Clear() override;
  bool ConsumeIntoMember(ParsingState& serialized) override;
  bool SerializeWithTagInto(SerializationState& out) const override;
  size_t GetSerializedSizeIncludingTag() const override;

  bool has_value() const { return value_.has_value(); }
  void set_value(absl::string_view value);
  const std::string& value() const;
  std::string* mutable_value();

 private:
  bool RequiresSerialization() const;

  const std::string& default_value() const;

  std::optional<std::string> value_;
  ProtoFieldOptions options_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_OWNING_FIELDS_H_
