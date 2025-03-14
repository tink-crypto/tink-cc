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

#include <cstdint>
#include <string>
#include <string_view>

#include "tink/internal/proto_parser.h"
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

struct KeyTemplateStruct {
  std::string type_url;
  std::string value;
  OutputPrefixTypeEnum output_prefix_type;

  static ProtoParser<KeyTemplateStruct> CreateParser();
  static const ProtoParser<KeyTemplateStruct>& GetParser();
};

struct KeyDataStruct {
  std::string type_url;
  util::SecretData value;
  KeyMaterialTypeEnum key_material_type;

  static ProtoParser<KeyDataStruct> CreateParser();
  static const ProtoParser<KeyDataStruct>& GetParser();
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_TINK_PROTO_STRUCTS_H_
