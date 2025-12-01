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

#ifndef TINK_INTERNAL_PROTO_PARSER_REPEATED_SECRET_DATA_FIELD_H_
#define TINK_INTERNAL_PROTO_PARSER_REPEATED_SECRET_DATA_FIELD_H_

#include <cstddef>
#include <vector>

#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

// RepeatedSecretDataField is a Field that owns a vector of SecretData.
// It is used to represent a repeated field of SecretData in a proto message.
class RepeatedSecretDataField : public Field {
 public:
  explicit RepeatedSecretDataField(int field_number);

  // Copyable and movable.
  RepeatedSecretDataField(const RepeatedSecretDataField&) = default;
  RepeatedSecretDataField& operator=(const RepeatedSecretDataField&) = default;
  RepeatedSecretDataField(RepeatedSecretDataField&&) noexcept = default;
  RepeatedSecretDataField& operator=(RepeatedSecretDataField&&) noexcept =
      default;

  void Clear() override { value_.clear(); }
  bool ConsumeIntoMember(ParsingState& parsing_state) override;
  bool SerializeWithTagInto(
      SerializationState& serialization_state) const override;
  size_t GetSerializedSizeIncludingTag() const override;

  const std::vector<SecretData>& value() const { return value_; }
  std::vector<SecretData>& value() { return value_; }

 private:
  std::vector<SecretData> value_;
};

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_REPEATED_SECRET_DATA_FIELD_H_
