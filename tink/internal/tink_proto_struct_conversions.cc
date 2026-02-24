// Copyright 2026 Google LLC
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

#include "tink/internal/tink_proto_struct_conversions.h"

#include <utility>

#include "tink/internal/tink_proto_structs.h"
#include "tink/util/secret_data.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

KeyTemplateTP ToKeyTemplateTP(
    ::google::crypto::tink::KeyTemplate key_template) {
  KeyTemplateTP key_template_tp;
  key_template_tp.set_type_url(std::move(*key_template.mutable_type_url()));
  key_template_tp.set_value(std::move(*key_template.mutable_value()));
  key_template_tp.set_output_prefix_type(
      static_cast<OutputPrefixTypeTP>(key_template.output_prefix_type()));
  return key_template_tp;
}

::google::crypto::tink::KeyTemplate ToProtoKeyTemplate(
    KeyTemplateTP key_template) {
  ::google::crypto::tink::KeyTemplate key_template_proto;
  key_template_proto.set_type_url(key_template.type_url());
  key_template_proto.set_value(key_template.value());
  key_template_proto.set_output_prefix_type(
      static_cast<::google::crypto::tink::OutputPrefixType>(
          key_template.output_prefix_type()));
  return key_template_proto;
}

KeyDataTP ToKeyDataTP(::google::crypto::tink::KeyData key_data) {
  KeyDataTP key_data_tp;
  key_data_tp.set_type_url(std::move(*key_data.mutable_type_url()));
  key_data_tp.set_value(key_data.value());
  key_data_tp.set_key_material_type(
      static_cast<KeyMaterialTypeTP>(key_data.key_material_type()));
  return key_data_tp;
}

::google::crypto::tink::KeyData ToProtoKeyData(KeyDataTP key_data) {
  ::google::crypto::tink::KeyData key_data_proto;
  key_data_proto.set_type_url(key_data.type_url());
  key_data_proto.set_value(
      crypto::tink::util::SecretDataAsStringView(key_data.value()));
  key_data_proto.set_key_material_type(
      static_cast<::google::crypto::tink::KeyData::KeyMaterialType>(
          key_data.key_material_type()));
  return key_data_proto;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

