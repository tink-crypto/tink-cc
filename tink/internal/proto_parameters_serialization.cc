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

#include "tink/internal/proto_parameters_serialization.h"

#include <sys/stat.h>

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/internal/util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using ::google::crypto::tink::KeyTemplate;

absl::StatusOr<ProtoParametersSerialization>
ProtoParametersSerialization::Create(absl::string_view type_url,
                                     OutputPrefixTypeEnum output_prefix_type,
                                     absl::string_view serialized_proto) {
  if (!IsPrintableAscii(type_url)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Non-printable ASCII character in type URL.");
  }
  KeyTemplateStruct key_template_struct;
  key_template_struct.type_url = std::string(type_url);
  key_template_struct.output_prefix_type = output_prefix_type;
  key_template_struct.value = std::string(serialized_proto);
  return ProtoParametersSerialization(std::move(key_template_struct));
}

absl::StatusOr<ProtoParametersSerialization>
ProtoParametersSerialization::Create(KeyTemplate key_template) {
  if (!IsPrintableAscii(key_template.type_url())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Non-printable ASCII character in type URL.");
  }
  KeyTemplateStruct key_template_struct;
  key_template_struct.type_url = key_template.type_url();
  key_template_struct.output_prefix_type =
      static_cast<OutputPrefixTypeEnum>(key_template.output_prefix_type());
  key_template_struct.value = key_template.value();
  return ProtoParametersSerialization(std::move(key_template_struct));
}

absl::StatusOr<ProtoParametersSerialization>
ProtoParametersSerialization::Create(const KeyTemplateStruct& key_template) {
  if (!IsPrintableAscii(key_template.type_url)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Non-printable ASCII character in type URL.");
  }
  return ProtoParametersSerialization(key_template);
}

absl::StatusOr<ProtoParametersSerialization>
ProtoParametersSerialization::Create(const ProtoKeyTemplate& key_template) {
  if (!IsPrintableAscii(key_template.type_url())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Non-printable ASCII character in type URL.");
  }
  KeyTemplateStruct key_struct;
  key_struct.type_url = key_template.type_url();
  key_struct.output_prefix_type =
      static_cast<OutputPrefixTypeEnum>(key_template.output_prefix_type());
  key_struct.value = key_template.value();
  return ProtoParametersSerialization(std::move(key_struct));
}

bool ProtoParametersSerialization::EqualsWithPotentialFalseNegatives(
    const ProtoParametersSerialization& other) const {
  const ProtoParametersSerialization* that =
      dynamic_cast<const ProtoParametersSerialization*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (key_template_.type_url != that->key_template_.type_url) {
    return false;
  }
  if (key_template_.output_prefix_type !=
      that->key_template_.output_prefix_type) {
    return false;
  }
  if (key_template_.value != that->key_template_.value) {
    return false;
  }
  if (object_identifier_ != that->object_identifier_) {
    return false;
  }
  return true;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
