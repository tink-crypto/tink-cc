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

#ifndef TINK_INTERNAL_PROTO_PARSER_UINT64_FIELD_H_
#define TINK_INTERNAL_PROTO_PARSER_UINT64_FIELD_H_

#include <cstddef>
#include <cstdint>

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


// A field where the member variable is a uint64_t and the wire type is
// kVarint.
template <typename Struct>
class Uint64Field : public Field<Struct> {
 public:
  explicit Uint64Field(int field_number, uint64_t Struct::*value)
      : value_(value), field_number_(field_number) {}

  // Not copyable, not movable.
  Uint64Field(const Uint64Field&) = delete;
  Uint64Field& operator=(const Uint64Field&) = delete;
  Uint64Field(Uint64Field&&) noexcept = delete;
  Uint64Field& operator=(Uint64Field&&) noexcept = delete;

  void ClearMember(Struct& s) const override { s.*value_ = 0; }

  bool ConsumeIntoMember(ParsingState& serialized, Struct& s) const override {
    absl::StatusOr<uint64_t> result = ConsumeVarintIntoUint64(serialized);
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
    if (values.*value_ == 0) {
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
    if (values.*value_ == 0) {
      return 0;
    }
    return WireTypeAndFieldNumberLength(GetWireType(), GetFieldNumber()) +
           VarintLength(values.*value_);
  }

 private:
  uint64_t Struct::*value_;
  int field_number_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_UINT64_FIELD_H_

