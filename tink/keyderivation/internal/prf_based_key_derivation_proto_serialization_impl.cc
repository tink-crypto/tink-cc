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
////////////////////////////////////////////////////////////////////////////////

#include "tink/keyderivation/internal/prf_based_key_derivation_proto_serialization_impl.h"

#include <memory>

#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/global_serialization_registry.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"
#include "tink/parameters.h"
#include "tink/prf/prf_parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/prf_based_deriver.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::PrfBasedDeriverKeyFormat;

using PrfBasedKeyDerivationProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization,
                         PrfBasedKeyDerivationParameters>;
using PrfBasedKeyDerivationProtoParametersSerializerImpl =
    ParametersSerializerImpl<PrfBasedKeyDerivationParameters,
                             ProtoParametersSerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey";

util::StatusOr<std::unique_ptr<Parameters>> ParametersFromKeyTemplate(
    const KeyTemplate& key_template) {
  util::StatusOr<ProtoParametersSerialization> proto_params_serialization =
      ProtoParametersSerialization::Create(key_template);
  if (!proto_params_serialization.ok()) {
    return proto_params_serialization.status();
  }
  return GlobalSerializationRegistry().ParseParameters(
      *proto_params_serialization);
}

util::StatusOr<KeyTemplate> ParametersToKeyTemplate(
    const Parameters& parameters) {
  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      GlobalSerializationRegistry()
          .SerializeParameters<ProtoParametersSerialization>(parameters);
  if (!serialization.ok()) {
    return serialization.status();
  }

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  if (proto_serialization == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to serialize proto parameters.");
  }

  return proto_serialization->GetKeyTemplate();
}

util::StatusOr<PrfBasedKeyDerivationParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing PrfBasedKeyDerivationParameters.");
  }

  PrfBasedDeriverKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse PrfBasedKeyDerivationKeyFormat proto");
  }

  if (serialization.GetKeyTemplate().output_prefix_type() !=
      proto_key_format.params().derived_key_template().output_prefix_type()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsed output prefix type must match derived key output prefix type.");
  }

  util::StatusOr<std::unique_ptr<Parameters>> derived_key_parameters =
      ParametersFromKeyTemplate(
          proto_key_format.params().derived_key_template());
  if (!derived_key_parameters.ok()) {
    return derived_key_parameters.status();
  }

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      ParametersFromKeyTemplate(proto_key_format.prf_key_template());
  if (!parameters.ok()) {
    return parameters.status();
  }

  const PrfParameters* prf_parameters =
      dynamic_cast<const PrfParameters*>(parameters->get());
  if (prf_parameters == nullptr) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Non-PRF parameters stored in the `prf_key_template` field.");
  }

  return PrfBasedKeyDerivationParameters::Builder()
      .SetPrfParameters(*prf_parameters)
      .SetDerivedKeyParameters(**derived_key_parameters)
      .Build();
}

util::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const PrfBasedKeyDerivationParameters& parameters) {
  util::StatusOr<KeyTemplate> prf_key_template =
      ParametersToKeyTemplate(parameters.GetPrfParameters());
  if (!prf_key_template.ok()) {
    return prf_key_template.status();
  }

  util::StatusOr<KeyTemplate> derived_key_template =
      ParametersToKeyTemplate(parameters.GetDerivedKeyParameters());
  if (!derived_key_template.ok()) {
    return derived_key_template.status();
  }

  PrfBasedDeriverKeyFormat proto_key_format;
  *proto_key_format.mutable_prf_key_template() = *prf_key_template;
  *proto_key_format.mutable_params()->mutable_derived_key_template() =
      *derived_key_template;

  return ProtoParametersSerialization::Create(
      kTypeUrl, derived_key_template->output_prefix_type(),
      proto_key_format.SerializeAsString());
}

PrfBasedKeyDerivationProtoParametersParserImpl*
PrfBasedKeyDerivationProtoParametersParser() {
  static auto* parser = new PrfBasedKeyDerivationProtoParametersParserImpl(
      kTypeUrl, ParseParameters);
  return parser;
}

PrfBasedKeyDerivationProtoParametersSerializerImpl*
PrfBasedKeyDerivationProtoParametersSerializer() {
  static auto* serializer =
      new PrfBasedKeyDerivationProtoParametersSerializerImpl(
          kTypeUrl, SerializeParameters);
  return serializer;
}

}  // namespace

util::Status RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  util::Status status = registry.RegisterParametersParser(
      PrfBasedKeyDerivationProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterParametersSerializer(
      PrfBasedKeyDerivationProtoParametersSerializer());
}

util::Status RegisterPrfBasedKeyDerivationProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  util::Status status = builder.RegisterParametersParser(
      PrfBasedKeyDerivationProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterParametersSerializer(
      PrfBasedKeyDerivationProtoParametersSerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
