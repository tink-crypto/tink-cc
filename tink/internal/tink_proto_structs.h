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

#include <string>

#include "tink/internal/proto_parser.h"
#include "tink/util/secret_data.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

struct KeyTemplateStruct {
  std::string type_url;
  std::string value;
  google::crypto::tink::OutputPrefixType output_prefix_type;

  static ProtoParser<KeyTemplateStruct> CreateParser();
  static const ProtoParser<KeyTemplateStruct>& GetParser();
};

struct KeyDataStruct {
  std::string type_url;
  util::SecretData value;
  google::crypto::tink::KeyData::KeyMaterialType key_material_type;

  static ProtoParser<KeyDataStruct> CreateParser();
  static const ProtoParser<KeyDataStruct>& GetParser();
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_TINK_PROTO_STRUCTS_H_
