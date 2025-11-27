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

#include "tink/internal/proto_parser_enum_field.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <utility>

#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

EnumFieldBase::EnumFieldBase(int field_number,
                             std::function<bool(uint32_t)> is_valid,
                             uint32_t default_value, ProtoFieldOptions options)
    : Field(field_number, WireType::kVarint),
      is_valid_(std::move(is_valid)),
      default_value_(default_value),
      options_(options) {
  // NOTE: The following works because [1,2]:
  // 1. IMPLICIT enums must always be OPEN
  // 2. OPEN enums's first value must be 0.
  // 3. IMPLICIT enums cannot have a different first value than 0.
  //
  // https://protobuf.dev/programming-guides/proto3/#enum [2]
  // https://protobuf.dev/editions/features/#enum_type
  ABSL_CHECK(default_value_ == 0 || options_ != ProtoFieldOptions::kImplicit)
      << "Default value must be 0 if options are kImplicit.";
  Clear();
}

void EnumFieldBase::Clear() {
  if (options_ == ProtoFieldOptions::kAlwaysPresent ||
      options_ == ProtoFieldOptions::kImplicit) {
    set_value(default_value_);
  } else {
    value_.reset();
  }
}

bool EnumFieldBase::RequiresSerialization() const {
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
      return value() != default_value_;
    default:
      ABSL_DCHECK(false) << "Unknown options: " << static_cast<int>(options_);
      return false;
  }
}

bool EnumFieldBase::ConsumeIntoMember(ParsingState& serialized) {
  absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(serialized);
  if (!result.ok()) {
    return false;
  }
  if (!is_valid_(result.value())) {
    return true;
  }
  value_ = static_cast<uint32_t>(*result);
  return true;
}

bool EnumFieldBase::SerializeWithTagInto(SerializationState& out) const {
  if (!RequiresSerialization()) {
    return true;
  }
  if (!SerializeWireTypeAndFieldNumber(GetWireType(), FieldNumber(), out)) {
    return false;
  }
  return SerializeVarint(value(), out);
}
size_t EnumFieldBase::GetSerializedSizeIncludingTag() const {
  if (!RequiresSerialization()) {
    return 0;
  }
  return WireTypeAndFieldNumberLength(GetWireType(), FieldNumber()) +
         VarintLength(value());
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
