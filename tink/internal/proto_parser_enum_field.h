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
#include <functional>
#include <utility>

#include "absl/status/status.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

class EnumFieldBase : public Field {
 public:
  explicit EnumFieldBase(int field_number,
                         std::function<bool(uint32_t)> is_valid,
                         uint32_t default_value, ProtoFieldOptions options)
      : Field(field_number, WireType::kVarint),
        value_(default_value),
        is_valid_(std::move(is_valid)),
        default_value_(default_value),
        options_(options) {}

  void Clear() override;
  bool ConsumeIntoMember(ParsingState& serialized) override;
  absl::Status SerializeWithTagInto(SerializationState& out) const override;
  size_t GetSerializedSizeIncludingTag() const override;

 protected:
  uint32_t value_;

 private:
  bool RequiresSerialization() const;

  std::function<bool(uint32_t)> is_valid_;
  uint32_t default_value_;
  ProtoFieldOptions options_;
};

template <typename Enum>
class EnumField : public EnumFieldBase {
 public:
  explicit EnumField(int field_number, std::function<bool(uint32_t)> is_valid,
                     Enum default_value = {},
                     ProtoFieldOptions options = ProtoFieldOptions::kImplicit)
      : EnumFieldBase(field_number, std::move(is_valid),
                      static_cast<uint32_t>(default_value), options) {}

  // Copyable and movable.
  EnumField(const EnumField&) = default;
  EnumField& operator=(const EnumField&) = default;
  EnumField(EnumField&&) noexcept = default;
  EnumField& operator=(EnumField&&) noexcept = default;

  Enum value() const { return static_cast<Enum>(value_); }
  void set_value(Enum value) { value_ = static_cast<uint32_t>(value); }
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_ENUM_FIELD_H_
