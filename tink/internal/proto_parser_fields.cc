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
#include <string>

#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// Uint32Field.

Uint32Field::Uint32Field(uint32_t field_number, ProtoFieldOptions options)
    : Field(field_number, WireType::kVarint), options_(options) {
  Clear();
}

bool Uint32Field::RequiresSerialization() const {
  switch (options_) {
    case ProtoFieldOptions::kExplicit:
      // With kExplicit, value_ is serialized only if it has a value.
      return value_.has_value();
    case ProtoFieldOptions::kAlwaysPresent:
      // With kAlwaysPresent, value_ is always set and is always serialized.
      return true;
    case ProtoFieldOptions::kImplicit:
      // With kImplicit, value_ is always set and is serialized only if it is
      // not equal to the default value.
      return value() != 0;
  }
  // TODO - handle this better.
  return true;
}

void Uint32Field::Clear() {
  if (options_ == ProtoFieldOptions::kAlwaysPresent ||
      options_ == ProtoFieldOptions::kImplicit) {
    value_ = 0;
  } else {
    value_.reset();
  }
}

bool Uint32Field::ConsumeIntoMember(ParsingState& serialized) {
  absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(serialized);
  if (!result.ok()) {
    return false;
  }
  value_ = *result;
  return true;
}

bool Uint32Field::SerializeWithTagInto(SerializationState& out) const {
  if (!RequiresSerialization()) {
    return true;
  }
  absl::Status status =
      SerializeWireTypeAndFieldNumber(GetWireType(), FieldNumber(), out);
  if (!status.ok()) {
    return false;
  }
  return SerializeVarint(*value_, out).ok();
}

size_t Uint32Field::GetSerializedSizeIncludingTag() const {
  if (!RequiresSerialization()) {
    return 0;
  }
  return WireTypeAndFieldNumberLength(GetWireType(), FieldNumber()) +
         VarintLength(*value_);
}

// Uint64Field.

Uint64Field::Uint64Field(uint64_t field_number, ProtoFieldOptions options)
    : Field(field_number, WireType::kVarint), options_(options) {
  Clear();
}

bool Uint64Field::RequiresSerialization() const {
  switch (options_) {
    case ProtoFieldOptions::kExplicit:
      // With kExplicit, value_ is serialized only if it has a value.
      return value_.has_value();
    case ProtoFieldOptions::kAlwaysPresent:
      // With kAlwaysPresent, value_ is always set and is always serialized.
      return true;
    case ProtoFieldOptions::kImplicit:
      // With kImplicit, value_ is always set and is serialized only if it is
      // not equal to the default value.
      return value() != 0ull;
  }
  // TODO - handle this better.
  return true;
}

void Uint64Field::Clear() {
  if (options_ == ProtoFieldOptions::kAlwaysPresent ||
      options_ == ProtoFieldOptions::kImplicit) {
    value_ = 0;
  } else {
    value_.reset();
  }
}

bool Uint64Field::ConsumeIntoMember(ParsingState& serialized) {
  absl::StatusOr<uint64_t> result = ConsumeVarintIntoUint64(serialized);
  if (!result.ok()) {
    return false;
  }
  value_ = *result;
  return true;
}
bool Uint64Field::SerializeWithTagInto(SerializationState& out) const {
  if (!RequiresSerialization()) {
    return true;
  }
  absl::Status status =
      SerializeWireTypeAndFieldNumber(GetWireType(), FieldNumber(), out);
  if (!status.ok()) {
    return false;
  }
  return SerializeVarint(*value_, out).ok();
}

size_t Uint64Field::GetSerializedSizeIncludingTag() const {
  if (!RequiresSerialization()) {
    return 0;
  }
  return WireTypeAndFieldNumberLength(GetWireType(), FieldNumber()) +
         VarintLength(*value_);
}

// BytesField.

bool BytesField::RequiresSerialization() const {
  switch (options_) {
    case ProtoFieldOptions::kExplicit:
      // With kExplicit, value_ is serialized only if it has a value.
      return value_.has_value();
    case ProtoFieldOptions::kAlwaysPresent:
      // With kAlwaysPresent, value_ is always set and is always serialized.
      return true;
    case ProtoFieldOptions::kImplicit:
      // With kImplicit, value_ is always set and is serialized only if it is
      // not equal to the default value.
      return *value_ != default_value();
    default:
      ABSL_DCHECK(false) << "Unknown options: " << static_cast<int>(options_);
      return false;
  }
}

BytesField::BytesField(uint32_t field_number, ProtoFieldOptions options)
    : Field(field_number, WireType::kLengthDelimited), options_(options) {
  Clear();
}

void BytesField::Clear() {
  if (options_ == ProtoFieldOptions::kAlwaysPresent ||
      options_ == ProtoFieldOptions::kImplicit) {
    value_.emplace();
  } else {
    value_.reset();
  }
}

bool BytesField::ConsumeIntoMember(ParsingState& serialized) {
  absl::StatusOr<absl::string_view> result =
      ConsumeBytesReturnStringView(serialized);
  if (!result.ok()) {
    return false;
  }
  set_value(*result);
  return true;
}

bool BytesField::SerializeWithTagInto(SerializationState& out) const {
  if (!RequiresSerialization()) {
    return true;
  }

  if (absl::Status result =
          SerializeWireTypeAndFieldNumber(GetWireType(), FieldNumber(), out);
      !result.ok()) {
    return false;
  }
  const size_t size = value_->size();
  if (absl::Status result = SerializeVarint(size, out); !result.ok()) {
    return false;
  }
  if (out.GetBuffer().size() < size) {
    return false;
  }
  // size is guaranteed to be <= out.GetBuffer().size().
  value_->copy(out.GetBuffer().data(), size);
  out.Advance(size);
  return true;
}

size_t BytesField::GetSerializedSizeIncludingTag() const {
  if (!RequiresSerialization()) {
    return 0;
  }
  const size_t size = value_->size();
  return WireTypeAndFieldNumberLength(GetWireType(), FieldNumber()) +
         VarintLength(size) + size;
}

void BytesField::set_value(absl::string_view value) {
  value_ = std::string(value);
}

const std::string& BytesField::value() const {
  if (!value_.has_value()) {
    return default_value();
  }
  return *value_;
}

std::string* BytesField::mutable_value() {
  if (!value_.has_value()) {
    value_.emplace();
  }
  return &*value_;
}

const std::string& BytesField::default_value() const {
  static const absl::NoDestructor<std::string> kDefaultValue;
  return *kDefaultValue;
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
