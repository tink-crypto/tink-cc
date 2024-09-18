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

#ifndef TINK_INTERNAL_PROTO_PARSER_ENUM_FIELD_H_
#define TINK_INTERNAL_PROTO_PARSER_ENUM_FIELD_H_

#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>
#include <utility>

#include "absl/functional/any_invocable.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

template <typename Struct, typename Enum>
class EnumField : public Field<Struct> {
 public:
  explicit EnumField(int tag, Enum Struct::*value,
                     absl::AnyInvocable<bool(uint32_t) const> is_valid,
                     ProtoFieldOptions options = ProtoFieldOptions::kNone)
      : tag_(tag),
        value_(value),
        is_valid_(std::move(is_valid)),
        options_(options) {
    static_assert(std::numeric_limits<std::underlying_type_t<Enum>>::max() <=
                      std::numeric_limits<uint32_t>::max(),
                  "Only sizes up to uint32_t are supported as underlying type");
    CHECK(is_valid_(0)) << "0 needs to be valid for EnumField.";
  }

  // Not copyable, not movable.
  EnumField(const EnumField&) = delete;
  EnumField& operator=(const EnumField&) = delete;
  EnumField(EnumField&&) noexcept = delete;
  EnumField& operator=(EnumField&&) noexcept = delete;

  void ClearMember(Struct& s) const override {
    s.*value_ = {};
  }

  absl::Status ConsumeIntoMember(ParsingState& serialized,
                                 Struct& s) const override {
    absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(serialized);
    if (!result.ok()) {
      return result.status();
    }
    if (!is_valid_(result.value())) {
      return absl::InvalidArgumentError(
          absl::StrCat("Invalid value for enum: ", *result));
    }
    s.*value_ = static_cast<Enum>(*result);
    return absl::OkStatus();
  }

  bool RequiresSerialization(const Struct& values) const override {
    return (options_ == ProtoFieldOptions::kAlwaysSerialize) ||
           values.*value_ != static_cast<Enum>(0);
  }

  absl::Status SerializeInto(absl::Span<char>& out,
                             const Struct& values) const override {
    return SerializeVarint(static_cast<uint32_t>(values.*value_), out);
  }

  size_t GetSerializedSize(const Struct& values) const override {
    return VarintLength(static_cast<uint32_t>(values.*value_));
  }

  WireType GetWireType() const override { return WireType::kVarint; }
  int GetTag() const override { return tag_; }

 private:
  int tag_;
  Enum Struct::*value_;
  absl::AnyInvocable<bool(uint32_t) const> is_valid_;
  ProtoFieldOptions options_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_ENUM_FIELD_H_
