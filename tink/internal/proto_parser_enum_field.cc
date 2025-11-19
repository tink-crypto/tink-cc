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

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

void EnumFieldBase::Clear() { value_ = default_value_; }
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
absl::Status EnumFieldBase::SerializeWithTagInto(
    SerializationState& out) const {
  if (!RequiresSerialization()) {
    return absl::OkStatus();
  }
  absl::Status status =
      SerializeWireTypeAndFieldNumber(GetWireType(), FieldNumber(), out);
  if (!status.ok()) {
    return status;
  }
  return SerializeVarint(static_cast<uint32_t>(value_), out);
}
size_t EnumFieldBase::GetSerializedSizeIncludingTag() const {
  if (!RequiresSerialization()) {
    return 0;
  }
  return WireTypeAndFieldNumberLength(GetWireType(), FieldNumber()) +
         VarintLength(static_cast<uint32_t>(value_));
}

bool EnumFieldBase::RequiresSerialization() const {
  return (options_ == ProtoFieldOptions::kAlwaysPresent) ||
         value_ != default_value_;
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
