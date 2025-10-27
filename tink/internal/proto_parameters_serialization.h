// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_INTERNAL_PROTO_PARAMETERS_SERIALIZATION_H_
#define TINK_INTERNAL_PROTO_PARAMETERS_SERIALIZATION_H_

#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/serialization.h"
#include "tink/internal/tink_proto_structs.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

// Represents a `Parameters` object serialized with binary protocol buffer
// serialization.
class ProtoParametersSerialization : public Serialization {
 public:
  // Copyable and movable.
  ProtoParametersSerialization(const ProtoParametersSerialization& other) =
      default;
  ProtoParametersSerialization& operator=(
      const ProtoParametersSerialization& other) = default;
  ProtoParametersSerialization(ProtoParametersSerialization&& other) = default;
  ProtoParametersSerialization& operator=(
      ProtoParametersSerialization&& other) = default;

  // Creates a `ProtoParametersSerialization` object from individual components.
  static absl::StatusOr<ProtoParametersSerialization> Create(
      absl::string_view type_url, OutputPrefixTypeEnum output_prefix_type,
      absl::string_view serialized_proto);

  // Creates a `ProtoParametersSerialization` object from a key template.
  static absl::StatusOr<ProtoParametersSerialization> Create(
      google::crypto::tink::KeyTemplate key_template);

  // Creates a `ProtoParametersSerialization` object from a key template struct.
  static absl::StatusOr<ProtoParametersSerialization> Create(
      const KeyTemplateStruct& key_template);

  // Creates a `ProtoParametersSerialization` object from a key template
  // proto message.
  static absl::StatusOr<ProtoParametersSerialization> Create(
      const ProtoKeyTemplate& key_template);

  const KeyTemplateStruct& GetKeyTemplateStruct() const {
    return key_template_;
  }

  absl::string_view ObjectIdentifier() const override {
    return object_identifier_;
  }

 private:
  // The following friend classes require access to
  // `EqualsWithPotentialFalseNegatives()`.
  friend class ProtoParametersSerializationTest;
  friend class LegacyProtoParameters;
  friend class LegacyProtoParametersTest;

  explicit ProtoParametersSerialization(KeyTemplateStruct key_template)
      : key_template_(std::move(key_template)),
        object_identifier_(key_template_.type_url) {}

  // Returns `true` if this `ProtoParametersSerialization` object is equal to
  // `other` (with the possibility of false negatives due to lack of
  // determinism during serialization).  Should only be used temporarily by the
  // `LegacyProtoParameters` class.
  bool EqualsWithPotentialFalseNegatives(
      const ProtoParametersSerialization& other) const;

  KeyTemplateStruct key_template_;
  std::string object_identifier_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARAMETERS_SERIALIZATION_H_
