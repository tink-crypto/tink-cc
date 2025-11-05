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
#include <type_traits>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parser_string_like_helpers.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/secret_data.h"

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

  // Copyable and movable.
  OwningField(const OwningField&) = default;
  OwningField& operator=(const OwningField&) = default;
  OwningField(OwningField&&) noexcept = default;
  OwningField& operator=(OwningField&&) noexcept = default;

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

class Uint32OwningField : public OwningField {
 public:
  explicit Uint32OwningField(
      uint32_t field_number,
      ProtoFieldOptions options = ProtoFieldOptions::kNone)
      : OwningField(field_number, WireType::kVarint), options_(options) {}

  // Copyable and movable.
  Uint32OwningField(const Uint32OwningField&) = default;
  Uint32OwningField& operator=(const Uint32OwningField&) = default;
  Uint32OwningField(Uint32OwningField&&) noexcept = default;
  Uint32OwningField& operator=(Uint32OwningField&&) noexcept = default;

  void Clear() override { value_ = 0; }
  bool ConsumeIntoMember(ParsingState& serialized) override {
    absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(serialized);
    if (!result.ok()) {
      return false;
    }
    value_ = *result;
    return true;
  }
  absl::Status SerializeWithTagInto(SerializationState& out) const override {
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
  size_t GetSerializedSizeIncludingTag() const override {
    if (!RequiresSerialization()) {
      return 0;
    }
    return WireTypeAndFieldNumberLength(GetWireType(), FieldNumber()) +
           VarintLength(value_);
  }

  void set_value(uint32_t value) { value_ = value; }
  uint32_t value() const { return value_; }

 private:
  bool RequiresSerialization() const {
    return options_ == ProtoFieldOptions::kAlwaysSerialize || value_ != 0;
  }

  uint32_t value_ = 0;
  ProtoFieldOptions options_;
};

class Uint64OwningField : public OwningField {
 public:
  explicit Uint64OwningField(uint64_t field_number)
      : OwningField(field_number, WireType::kVarint) {}

  // Copyable and movable.
  Uint64OwningField(const Uint64OwningField&) = default;
  Uint64OwningField& operator=(const Uint64OwningField&) = default;
  Uint64OwningField(Uint64OwningField&&) noexcept = default;
  Uint64OwningField& operator=(Uint64OwningField&&) noexcept = default;

  void Clear() override { value_ = 0; }

  bool ConsumeIntoMember(ParsingState& serialized) override {
    absl::StatusOr<uint64_t> result = ConsumeVarintIntoUint64(serialized);
    if (!result.ok()) {
      return false;
    }
    value_ = *result;
    return true;
  }

  absl::Status SerializeWithTagInto(SerializationState& out) const override {
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

  size_t GetSerializedSizeIncludingTag() const override {
    if (value_ == 0) {
      return 0;
    }
    return WireTypeAndFieldNumberLength(GetWireType(), FieldNumber()) +
           VarintLength(value_);
  }

  void set_value(uint64_t value) { value_ = value; }
  uint64_t value() const { return value_; }

 private:
  uint64_t value_ = 0;
};

template <typename StringLike>
class OwningBytesField final : public OwningField {
 public:
  static_assert(!std::is_same<StringLike, ::crypto::tink::SecretData>::value,
                "Use SecretDataField instead");

  explicit OwningBytesField(uint32_t field_number, ProtoFieldOptions options =
                                                       ProtoFieldOptions::kNone)
      : OwningField(field_number, WireType::kLengthDelimited),
        options_(options) {}
  // Copyable and movable.
  OwningBytesField(const OwningBytesField&) = default;
  OwningBytesField& operator=(const OwningBytesField&) = default;
  OwningBytesField(OwningBytesField&&) noexcept = default;
  OwningBytesField& operator=(OwningBytesField&&) noexcept = default;

  void Clear() override { ClearStringLikeValue(value_); }
  bool ConsumeIntoMember(ParsingState& serialized) override {
    absl::StatusOr<absl::string_view> result =
        ConsumeBytesReturnStringView(serialized);
    if (!result.ok()) {
      return false;
    }
    CopyIntoStringLikeValue(*result, value_);
    return true;
  }
  absl::Status SerializeWithTagInto(SerializationState& out) const override {
    if (!RequiresSerialization()) {
      return absl::OkStatus();
    }

    if (absl::Status result =
            SerializeWireTypeAndFieldNumber(GetWireType(), FieldNumber(), out);
        !result.ok()) {
      return result;
    }
    size_t size = SizeOfStringLikeValue(value_);

    if (absl::Status result = SerializeVarint(size, out); !result.ok()) {
      return result;
    }
    if (out.GetBuffer().size() < size) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Output buffer too small: ", out.GetBuffer().size(), " < ", size));
    }
    SerializeStringLikeValue(value_, out.GetBuffer());
    out.Advance(size);
    return absl::OkStatus();
  }

  size_t GetSerializedSizeIncludingTag() const override {
    if (!RequiresSerialization()) {
      return 0;
    }
    size_t size = SizeOfStringLikeValue(value_);
    return WireTypeAndFieldNumberLength(GetWireType(), FieldNumber()) +
           VarintLength(size) + size;
  }

  void set_value(absl::string_view value) {
    CopyIntoStringLikeValue(value, value_);
  }
  const StringLike& value() const { return value_; }
  StringLike* mutable_value() { return &value_; }

 private:
  bool RequiresSerialization() const {
    return options_ == ProtoFieldOptions::kAlwaysSerialize ||
           SizeOfStringLikeValue(value_) != 0;
  }

  StringLike value_;
  ProtoFieldOptions options_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_OWNING_FIELDS_H_
