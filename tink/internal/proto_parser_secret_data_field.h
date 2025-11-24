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
#ifndef TINK_INTERNAL_PROTO_PARSER_SECRET_DATA_FIELD_H_
#define TINK_INTERNAL_PROTO_PARSER_SECRET_DATA_FIELD_H_

#include <cstddef>
#include <cstdint>
#include <optional>

#include "absl/status/status.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// SecretDataField is a Field that owns a SecretData.
//
// Note:
// * if options == ProtoFieldOptions::kAlwaysPresent, then the field is
//   always present (i.e., has_value() never returns false). This forces
//   serialization as well, which is useful if the field is LEGACY_REQUIRED in
//   proto.
// * if options == ProtoFieldOptions::kNone, then the field is serialized
//   only if the value is set (even if with a default value).
//
// This class is not thread-safe.
class SecretDataField final : public Field {
 public:
  explicit SecretDataField(uint32_t field_number, ProtoFieldOptions options =
                                                      ProtoFieldOptions::kNone);
  // Copyable and movable.
  SecretDataField(const SecretDataField&) = default;
  SecretDataField& operator=(const SecretDataField&) = default;
  SecretDataField(SecretDataField&&) noexcept = default;
  SecretDataField& operator=(SecretDataField&&) noexcept = default;

  void Clear() override;
  bool ConsumeIntoMember(ParsingState& serialized) override;
  absl::Status SerializeWithTagInto(SerializationState& out) const override;
  size_t GetSerializedSizeIncludingTag() const override;

  bool has_value() const;
  const SecretData& value() const;
  SecretData* mutable_value();

 private:
  const SecretData& default_value() const;

  std::optional<SecretData> value_;
  ProtoFieldOptions options_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_SECRET_DATA_FIELD_H_
