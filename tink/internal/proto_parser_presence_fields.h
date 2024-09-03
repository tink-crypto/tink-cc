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

#ifndef TINK_INTERNAL_PROTO_PARSER_PRESENCE_FIELDS_H_
#define TINK_INTERNAL_PROTO_PARSER_PRESENCE_FIELDS_H_

#include <cstddef>
#include <cstdint>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parsing_helpers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

template <typename Struct>
class Uint32FieldWithPresence : public Field<Struct> {
 public:
  explicit Uint32FieldWithPresence(int tag,
                                   absl::optional<uint32_t> Struct::*value)
      : value_(value), tag_(tag) {}

  // Not copyable, not movable.
  Uint32FieldWithPresence(const Uint32FieldWithPresence&) = delete;
  Uint32FieldWithPresence& operator=(const Uint32FieldWithPresence&) = delete;
  Uint32FieldWithPresence(Uint32FieldWithPresence&&) noexcept = delete;
  Uint32FieldWithPresence& operator=(Uint32FieldWithPresence&&) noexcept =
      delete;

  void ClearMember(Struct& s) const override { (s.*value_).reset(); }

  absl::Status ConsumeIntoMember(absl::string_view& serialized,
                                 Struct& s) const override {
    absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(serialized);
    if (!result.ok()) {
      return result.status();
    }
    s.*value_ = *result;
    return absl::OkStatus();
  }

  bool RequiresSerialization(const Struct& values) const override {
    return (values.*value_).has_value();
  }

  absl::Status SerializeInto(absl::Span<char>& out,
                             const Struct& values) const override {
    if (!(values.*value_).has_value()) {
      return absl::InvalidArgumentError(
          "Must not call SerializeInto on absent Uint32FieldWithPresence");
    }
    return SerializeVarint(*(values.*value_), out);
  }

  size_t GetSerializedSize(const Struct& values) const override {
    if (!(values.*value_).has_value()) {
      // We should never get here.
      return 0;
    }
    return VarintLength(*(values.*value_));
  }

  WireType GetWireType() const override { return WireType::kVarint; }
  int GetTag() const override { return tag_; }

 private:
  absl::optional<uint32_t> Struct::*value_;
  int tag_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_PRESENCE_FIELDS_H_
