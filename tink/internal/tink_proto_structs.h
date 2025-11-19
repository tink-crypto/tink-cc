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
#ifndef TINK_INTERNAL_TINK_PROTO_STRUCTS_H_
#define TINK_INTERNAL_TINK_PROTO_STRUCTS_H_

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include "absl/strings/string_view.h"
#include "tink/internal/proto_parser_enum_field.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_secret_data_field.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

// Enum representing the output prefix type of a key.
// It represents the proto enum `google.crypto.tink.OutputPrefixType`.
enum class OutputPrefixTypeEnum : uint32_t {
  kUnknownPrefix = 0,
  kTink,
  kLegacy,
  kRaw,
  kCrunchy,
  kWithIdRequirement,
};

std::string_view OutputPrefixTypeEnumName(OutputPrefixTypeEnum type);

inline bool OutputPrefixTypeValid(int c) { return c >= 0 && c <= 5; }

// Enum representing the key material type of a key.
// It represents the proto enum `google.crypto.tink.KeyData.KeyMaterialType`.
enum class KeyMaterialTypeEnum : uint32_t {
  kUnknownKeyMaterial = 0,
  kSymmetric,
  kAsymmetricPrivate,
  kAsymmetricPublic,
  kRemote,
};

std::string_view KeyMaterialTypeEnumName(KeyMaterialTypeEnum type);

inline bool KeyMaterialTypeValid(int c) { return c >= 0 && c <= 4; }

class KeyTemplateTP : public proto_parsing::Message {
 public:
  KeyTemplateTP() = default;

  // Copyable and movable.
  KeyTemplateTP(const KeyTemplateTP&) = default;
  KeyTemplateTP& operator=(const KeyTemplateTP&) = default;
  KeyTemplateTP(KeyTemplateTP&&) noexcept = default;
  KeyTemplateTP& operator=(KeyTemplateTP&&) noexcept = default;

  // This is OK because it doesn't contain any secret data.
  using Message::SerializeAsString;

  const std::string& type_url() const { return type_url_.value(); }
  void set_type_url(absl::string_view type_url) {
    type_url_.set_value(type_url);
  }

  const std::string& value() const { return value_.value(); }
  void set_value(absl::string_view value) { value_.set_value(value); }

  OutputPrefixTypeEnum output_prefix_type() const {
    return output_prefix_type_.value();
  }
  void set_output_prefix_type(OutputPrefixTypeEnum output_prefix_type) {
    output_prefix_type_.set_value(output_prefix_type);
  }

 private:
  size_t num_fields() const override { return 3; }
  const proto_parsing::Field* field(int i) const override {
    return std::array<const proto_parsing::Field*, 3>{&type_url_, &value_,
                                                      &output_prefix_type_}[i];
  }

  proto_parsing::BytesField type_url_{1};
  proto_parsing::BytesField value_{2};
  proto_parsing::EnumField<OutputPrefixTypeEnum> output_prefix_type_{
      3, &OutputPrefixTypeValid};
};

class KeyDataTP : public proto_parsing::Message {
 public:
  KeyDataTP() = default;

  // Copyable and movable.
  KeyDataTP(const KeyDataTP&) = default;
  KeyDataTP& operator=(const KeyDataTP&) = default;
  KeyDataTP(KeyDataTP&&) noexcept = default;
  KeyDataTP& operator=(KeyDataTP&&) noexcept = default;

  // Note: Serialization is not public, as this contains secret key material.

  const std::string& type_url() const { return type_url_.value(); }
  void set_type_url(absl::string_view type_url) {
    type_url_.set_value(type_url);
  }

  const SecretData& value() const { return value_.value(); }
  void set_value(absl::string_view value) {
    *value_.mutable_value() = util::SecretDataFromStringView(value);
  }

  KeyMaterialTypeEnum key_material_type() const {
    return key_material_type_.value();
  }
  void set_key_material_type(KeyMaterialTypeEnum key_material_type) {
    key_material_type_.set_value(key_material_type);
  }

 private:
  size_t num_fields() const override { return 3; }
  const proto_parsing::Field* field(int i) const override {
    return std::array<const proto_parsing::Field*, 3>{&type_url_, &value_,
                                                      &key_material_type_}[i];
  }

  proto_parsing::BytesField type_url_{1};
  proto_parsing::SecretDataField value_{2};
  proto_parsing::EnumField<KeyMaterialTypeEnum> key_material_type_{
      3, &KeyMaterialTypeValid};
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_TINK_PROTO_STRUCTS_H_
