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
#include "tink/internal/proto_parser.h"
#include "tink/internal/proto_parser_enum_field.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/secret_data.h"

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

class ProtoKeyTemplate : public proto_parsing::Message<ProtoKeyTemplate> {
 public:
  ProtoKeyTemplate() = default;

  // Copyable and movable.
  ProtoKeyTemplate(const ProtoKeyTemplate&) = default;
  ProtoKeyTemplate& operator=(const ProtoKeyTemplate&) = default;
  ProtoKeyTemplate(ProtoKeyTemplate&&) noexcept = default;
  ProtoKeyTemplate& operator=(ProtoKeyTemplate&&) noexcept = default;

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

  std::array<const proto_parsing::OwningField*, 3> GetFields() const {
    return {&type_url_, &value_, &output_prefix_type_};
  }

 private:
  proto_parsing::OwningBytesField<std::string> type_url_{1};
  proto_parsing::OwningBytesField<std::string> value_{2};
  proto_parsing::EnumOwningField<OutputPrefixTypeEnum> output_prefix_type_{
      3, &OutputPrefixTypeValid};
};

class ProtoKeyData : public proto_parsing::Message<ProtoKeyData> {
 public:
  ProtoKeyData() = default;

  // Copyable and movable.
  ProtoKeyData(const ProtoKeyData&) = default;
  ProtoKeyData& operator=(const ProtoKeyData&) = default;
  ProtoKeyData(ProtoKeyData&&) noexcept = default;
  ProtoKeyData& operator=(ProtoKeyData&&) noexcept = default;

  // Note: Serialization is not public, as this contains secret key material.

  const std::string& type_url() const { return type_url_.value(); }
  void set_type_url(absl::string_view type_url) {
    type_url_.set_value(type_url);
  }

  const SecretData& value() const { return value_.value(); }
  void set_value(absl::string_view value) { value_.set_value(value); }

  KeyMaterialTypeEnum key_material_type() const {
    return key_material_type_.value();
  }
  void set_key_material_type(KeyMaterialTypeEnum key_material_type) {
    key_material_type_.set_value(key_material_type);
  }

  std::array<const proto_parsing::OwningField*, 3> GetFields() const {
    return {&type_url_, &value_, &key_material_type_};
  }

 private:
  proto_parsing::OwningBytesField<std::string> type_url_{1};
  proto_parsing::OwningBytesField<SecretData> value_{2};
  proto_parsing::EnumOwningField<KeyMaterialTypeEnum> key_material_type_{
      3, &KeyMaterialTypeValid};
};

struct KeyTemplateStruct {
  std::string type_url;
  std::string value;
  OutputPrefixTypeEnum output_prefix_type;

  static ProtoParser<KeyTemplateStruct> CreateParser();
  static const ProtoParser<KeyTemplateStruct>& GetParser();
};

struct KeyDataStruct {
  std::string type_url;
  SecretData value;
  KeyMaterialTypeEnum key_material_type;

  static ProtoParser<KeyDataStruct> CreateParser();
  static const ProtoParser<KeyDataStruct>& GetParser();
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_TINK_PROTO_STRUCTS_H_
