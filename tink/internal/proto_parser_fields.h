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

#ifndef TINK_INTERNAL_PROTO_PARSER_FIELDS_H_
#define TINK_INTERNAL_PROTO_PARSER_FIELDS_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/big_integer.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/internal/safe_stringops.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// To implement a BytesField storing in a "StringType", one needs to implement
// the following functions:
//  * void ClearStringLikeValue(StringType& s);
//  * void CopyIntoStringLikeValue(string_view from, StringType& to);
//  * size_t SizeOfStringLikeValue(const StringType& s);
//  * void SerializeStringLikeValue(const StringType& s, absl::Span<char> o);
// After this, one can use BytesField<Struct, StringType>.

// Clears the value.
void ClearStringLikeValue(std::string& s);
void ClearStringLikeValue(SecretData& s);
void ClearStringLikeValue(absl::string_view& b);

// Copies the first argument into the second.
void CopyIntoStringLikeValue(absl::string_view sv, std::string& s);
void CopyIntoStringLikeValue(absl::string_view sv, SecretData& s);
void CopyIntoStringLikeValue(absl::string_view sv, absl::string_view& dest);

// Returns the size of the string like value.
size_t SizeOfStringLikeValue(const std::string& s);
size_t SizeOfStringLikeValue(const SecretData& s);
size_t SizeOfStringLikeValue(absl::string_view b);

// Serialize the string from the first argument into the second.
// Behavior in case that first.size() > second.size() is unimportant -- it will
// never be called like this.
void SerializeStringLikeValue(const std::string& s, absl::Span<char> o);
void SerializeStringLikeValue(const SecretData& s, absl::Span<char> o);
void SerializeStringLikeValue(absl::string_view s, absl::Span<char> o);

// Methods to parse a field in a proto message into some member in the struct
// "Struct".
//
// A Fields<Struct> has a method ConsumeIntoMember which populates exactly one
// member variable of the struct and some helper methods to facilitate this.
template <typename Struct>
class Field {
 public:
  virtual ~Field() = default;

  // Clears the field.
  virtual void ClearMember(Struct& values) const = 0;

  // Parse the serialization into the member managed by this field.
  //
  // The passed in |serialization| contains always data
  // after the initial bytes describing the "wire type and tag". If the wire
  // type is kLengthDelimited, "serialized" contains only the data of the
  // field. Otherwise, it contains all the data of the remaining serialized
  // message. The processed data needs to be removed.
  //
  // Returns true on success.
  ABSL_MUST_USE_RESULT
  virtual bool ConsumeIntoMember(ParsingState& serialized,
                                 Struct& values) const = 0;

  // Serializes the member into out, and removes the part which was written
  // on from out. Includes the tag of the field (the encoded wiretype/field
  // number). This is different from the parsing function "ConsumeIntoMember".
  virtual absl::Status SerializeWithTagInto(SerializationState& out,
                                            const Struct& values) const = 0;

  // Returns the required size for SerializeWithTagInto.
  virtual size_t GetSerializedSizeIncludingTag(const Struct& values) const = 0;
  virtual WireType GetWireType() const = 0;
  virtual int GetFieldNumber() const = 0;
};

// A field where the member variable is a uint32_t and the wire type is
// kVarint.
template <typename Struct>
class Uint32Field : public Field<Struct> {
 public:
  explicit Uint32Field(int field_number, uint32_t Struct::*value,
                       ProtoFieldOptions options = ProtoFieldOptions::kNone)
      : value_(value), field_number_(field_number), options_(options) {}

  // Not copyable, not movable.
  Uint32Field(const Uint32Field&) = delete;
  Uint32Field& operator=(const Uint32Field&) = delete;
  Uint32Field(Uint32Field&&) noexcept = delete;
  Uint32Field& operator=(Uint32Field&&) noexcept = delete;

  void ClearMember(Struct& s) const override { s.*value_ = 0; }

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
    return SerializeVarint(values.*value_, out);
  }

  size_t GetSerializedSizeIncludingTag(const Struct& values) const override {
    if (!RequiresSerialization(values)) {
      return 0;
    }
    return WireTypeAndFieldNumberLength(GetWireType(), GetFieldNumber()) +
           VarintLength(values.*value_);
  }

 private:
  bool RequiresSerialization(const Struct& values) const {
    return options_ == ProtoFieldOptions::kAlwaysSerialize ||
           values.*value_ != 0;
  }

  uint32_t Struct::*value_;
  int field_number_;
  ProtoFieldOptions options_;
};

template <typename Struct, typename StringLike>
class BytesField : public Field<Struct> {
 public:
  explicit BytesField(int tag, StringLike Struct::*value,
                      ProtoFieldOptions options = ProtoFieldOptions::kNone)
      : value_(value), field_number_(tag), options_(options) {}
  // Not copyable and movable.
  BytesField(const BytesField&) = delete;
  BytesField& operator=(const BytesField&) = delete;
  BytesField(BytesField&&) noexcept = delete;
  BytesField& operator=(BytesField&&) noexcept = delete;

  void ClearMember(Struct& s) const override {
    ClearStringLikeValue(s.*value_);
  }

  bool ConsumeIntoMember(ParsingState& serialized, Struct& s) const override {
    absl::StatusOr<absl::string_view> result =
        ConsumeBytesReturnStringView(serialized);
    if (!result.ok()) {
      return false;
    }
    CopyIntoStringLikeValue(*result, s.*value_);
    return true;
  }

  WireType GetWireType() const override { return WireType::kLengthDelimited; }
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
    size_t size = SizeOfStringLikeValue(values.*value_);
    absl::Status s = SerializeVarint(size, out);
    if (!s.ok()) {
      return s;
    }
    if (out.GetBuffer().size() < size) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Output buffer too small: ", out.GetBuffer().size(), " < ",
          size));
    }
    SerializeStringLikeValue(values.*value_, out.GetBuffer());
    out.Advance(size);
    return absl::OkStatus();
  }

  size_t GetSerializedSizeIncludingTag(const Struct& values) const override {
    if (!RequiresSerialization(values)) {
      return 0;
    }
    size_t size = SizeOfStringLikeValue(values.*value_);
    return WireTypeAndFieldNumberLength(GetWireType(), GetFieldNumber()) +
           VarintLength(size) + size;
  }

 private:
  bool RequiresSerialization(const Struct& values) const {
    return options_ == ProtoFieldOptions::kAlwaysSerialize ||
           SizeOfStringLikeValue(values.*value_) != 0;
  }

  StringLike Struct::*value_;
  int field_number_;
  ProtoFieldOptions options_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_FIELDS_H_
