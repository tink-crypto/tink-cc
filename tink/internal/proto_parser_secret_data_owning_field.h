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
#ifndef TINK_INTERNAL_PROTO_PARSER_SECRET_DATA_OWNING_FIELD_H_
#define TINK_INTERNAL_PROTO_PARSER_SECRET_DATA_OWNING_FIELD_H_

#include <cstddef>
#include <cstdint>

#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/internal/proto_parser_secret_data_field.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/internal/safe_stringops.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

class SecretDataOwningField final : public OwningField {
 public:
  explicit SecretDataOwningField(
      uint32_t field_number,
      ProtoFieldOptions options = ProtoFieldOptions::kNone)
      : OwningField(field_number, WireType::kLengthDelimited),
        field_(field_number, &SecretDataOwningField::value_, options) {}
  // Copyable and movable.
  SecretDataOwningField(const SecretDataOwningField&) = default;
  SecretDataOwningField& operator=(const SecretDataOwningField&) = default;
  SecretDataOwningField(SecretDataOwningField&&) noexcept = default;
  SecretDataOwningField& operator=(SecretDataOwningField&&) noexcept = default;

  void Clear() override { field_.ClearMember(*this); }
  bool ConsumeIntoMember(ParsingState& serialized) override {
    return field_.ConsumeIntoMember(serialized, *this);
  }
  absl::Status SerializeWithTagInto(SerializationState& out) const override {
    return field_.SerializeWithTagInto(out, *this);
  }
  size_t GetSerializedSizeIncludingTag() const override {
    return field_.GetSerializedSizeIncludingTag(*this);
  }

  const SecretData& value() const { return value_; }
  SecretData* mutable_value() { return &value_; }

 private:
  SecretData value_;
  SecretDataField<SecretDataOwningField> field_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_SECRET_DATA_OWNING_FIELD_H_
