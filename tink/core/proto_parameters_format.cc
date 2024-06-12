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

#include "tink/proto_parameters_format.h"

#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/legacy_proto_parameters.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

using ::google::crypto::tink::KeyTemplate;

util::StatusOr<std::string> SerializeParametersToProtoFormat(
    const Parameters& parameters) {
  const internal::LegacyProtoParameters* legacy_proto_params =
      dynamic_cast<const internal::LegacyProtoParameters*>(&parameters);
  if (legacy_proto_params != nullptr) {
    return legacy_proto_params->Serialization()
        .GetKeyTemplate()
        .SerializeAsString();
  }

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              parameters);
  if (!serialization.ok()) {
    return serialization.status();
  }

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  if (proto_serialization == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to serialize proto parameters.");
  }

  return proto_serialization->GetKeyTemplate().SerializeAsString();
}

util::StatusOr<std::unique_ptr<Parameters>> ParseParametersFromProtoFormat(
    absl::string_view serialized_parameters) {
  KeyTemplate key_template;
  if (!key_template.ParseFromString(serialized_parameters)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse proto parameters into key template.");
  }

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(key_template);
  if (!serialization.ok()) {
    return serialization.status();
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .ParseParametersWithLegacyFallback(*serialization);
}

}  // namespace tink
}  // namespace crypto
