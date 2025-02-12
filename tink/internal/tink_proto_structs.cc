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
#include "tink/internal/tink_proto_structs.h"

#include "absl/base/no_destructor.h"
#include "tink/internal/proto_parser.h"

namespace crypto {
namespace tink {
namespace internal {

bool OutputPrefixTypeValid(int c) {
  return google::crypto::tink::OutputPrefixType_IsValid(c);
}

bool KeyMaterialTypeValid(int c) {
  return google::crypto::tink::KeyData::KeyMaterialType_IsValid(c);
}

ProtoParser<KeyTemplateStruct> KeyTemplateStruct::CreateParser() {
  return ProtoParserBuilder<KeyTemplateStruct>()
      .AddBytesStringField(1, &KeyTemplateStruct::type_url)
      .AddBytesStringField(2, &KeyTemplateStruct::value)
      .AddEnumField(3, &KeyTemplateStruct::output_prefix_type,
                    &OutputPrefixTypeValid)
      .BuildOrDie();
}

const ProtoParser<KeyTemplateStruct>& KeyTemplateStruct::GetParser() {
  static const absl::NoDestructor<ProtoParser<KeyTemplateStruct>> parser(
      CreateParser());
  return *parser;
}

ProtoParser<KeyDataStruct> KeyDataStruct::CreateParser() {
  return ProtoParserBuilder<KeyDataStruct>()
      .AddBytesStringField(1, &KeyDataStruct::type_url)
      .AddBytesSecretDataField(2, &KeyDataStruct::value)
      .AddEnumField(3, &KeyDataStruct::key_material_type, &KeyMaterialTypeValid)
      .BuildOrDie();
}

const ProtoParser<KeyDataStruct>& KeyDataStruct::GetParser() {
  static const absl::NoDestructor<ProtoParser<KeyDataStruct>> parser(
      CreateParser());
  return *parser;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
