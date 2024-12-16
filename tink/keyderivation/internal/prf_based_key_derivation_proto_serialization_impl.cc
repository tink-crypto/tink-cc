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
#include <utility>

#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/global_serialization_registry.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/key.h"
#include "tink/keyderivation/prf_based_key_derivation_key.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/prf/prf_key.h"
#include "tink/prf/prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/prf_based_deriver.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::PrfBasedDeriverKey;
using ::google::crypto::tink::PrfBasedDeriverKeyFormat;

using PrfBasedKeyDerivationProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization,
                         PrfBasedKeyDerivationParameters>;
using PrfBasedKeyDerivationProtoParametersSerializerImpl =
    ParametersSerializerImpl<PrfBasedKeyDerivationParameters,
                             ProtoParametersSerialization>;
using PrfBasedKeyDerivationProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, PrfBasedKeyDerivationKey>;
using PrfBasedKeyDerivationProtoKeySerializerImpl =
    KeySerializerImpl<PrfBasedKeyDerivationKey, ProtoKeySerialization>;

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

util::StatusOr<std::unique_ptr<const PrfKey>> PrfKeyFromKeyData(
    const KeyData& key_data, SecretKeyAccessToken token) {
  util::StatusOr<ProtoKeySerialization> proto_key_serialization =
      ProtoKeySerialization::Create(
          key_data.type_url(), RestrictedData(key_data.value(), token),
          key_data.key_material_type(), OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  if (!proto_key_serialization.ok()) {
    return proto_key_serialization.status();
  }

  util::StatusOr<std::unique_ptr<Key>> key =
      GlobalSerializationRegistry().ParseKey(*proto_key_serialization, token);
  if (!key.ok()) {
    return key.status();
  }

  const PrfKey* prf_key = dynamic_cast<const PrfKey*>(key->get());
  if (prf_key == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Non-PRF key stored in the `prf_key` field.");
  }

  return absl::WrapUnique(dynamic_cast<const PrfKey*>(key->release()));
}

util::StatusOr<KeyData> PrfKeyToKeyData(const PrfKey& prf_key,
                                        SecretKeyAccessToken token) {
  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      GlobalSerializationRegistry().SerializeKey<ProtoKeySerialization>(prf_key,
                                                                        token);
  if (!serialization.ok()) {
    return serialization.status();
  }

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  if (proto_serialization == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to serialize proto key.");
  }

  KeyData key_data;
  key_data.set_value(util::SecretDataAsStringView(
      proto_serialization->SerializedKeyProto().Get(token)));
  key_data.set_type_url(proto_serialization->TypeUrl());
  key_data.set_key_material_type(proto_serialization->KeyMaterialType());

  return key_data;
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

util::StatusOr<PrfBasedKeyDerivationKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing PrfBasedKeyDerivationKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required.");
  }

  util::StatusOr<SecretProto<google::crypto::tink::PrfBasedDeriverKey>>
      proto_key = SecretProto<google::crypto::tink::PrfBasedDeriverKey>::
          ParseFromSecretData(serialization.SerializedKeyProto().Get(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse PrfBasedDeriverKey proto");
  }
  if ((*proto_key)->version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  if (serialization.GetOutputPrefixType() !=
      (*proto_key)->params().derived_key_template().output_prefix_type()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsed output prefix type must match derived key output prefix type.");
  }

  util::StatusOr<std::unique_ptr<Parameters>> derived_key_parameters =
      ParametersFromKeyTemplate((*proto_key)->params().derived_key_template());
  if (!derived_key_parameters.ok()) {
    return derived_key_parameters.status();
  }

  util::StatusOr<std::unique_ptr<const PrfKey>> prf_key =
      CallWithCoreDumpProtection(
          [&]() { return PrfKeyFromKeyData((*proto_key)->prf_key(), *token); });
  if (!prf_key.ok()) {
    return prf_key.status();
  }

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters((*prf_key)->GetParameters())
          .SetDerivedKeyParameters(**derived_key_parameters)
          .Build();
  if (!derived_key_parameters.ok()) {
    return derived_key_parameters.status();
  }

  return PrfBasedKeyDerivationKey::Create(*parameters, **prf_key,
                                          serialization.IdRequirement(),
                                          GetPartialKeyAccess());
}

util::StatusOr<ProtoKeySerialization> SerializeKey(
    const PrfBasedKeyDerivationKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required.");
  }

  util::StatusOr<KeyTemplate> derived_key_template =
      ParametersToKeyTemplate(key.GetParameters().GetDerivedKeyParameters());
  if (!derived_key_template.ok()) {
    return derived_key_template.status();
  }

  SecretProto<google::crypto::tink::PrfBasedDeriverKey> proto_key;
  proto_key->set_version(0);
  util::Status status = CallWithCoreDumpProtection([&]() {
    util::StatusOr<KeyData> prf_key_data =
        PrfKeyToKeyData(key.GetPrfKey(), *token);
    if (!prf_key_data.ok()) {
      return prf_key_data.status();
    }
    *proto_key->mutable_prf_key() = *prf_key_data;
    return util::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }
  *proto_key->mutable_params()->mutable_derived_key_template() =
      *derived_key_template;

  util::StatusOr<SecretData> serialized_key = proto_key.SerializeAsSecretData();
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*std::move(serialized_key), *token);
  return ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, google::crypto::tink::KeyData::SYMMETRIC,
      derived_key_template->output_prefix_type(), key.GetIdRequirement());
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

PrfBasedKeyDerivationProtoKeyParserImpl* PrfBasedKeyDerivationProtoKeyParser() {
  static auto* parser =
      new PrfBasedKeyDerivationProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

PrfBasedKeyDerivationProtoKeySerializerImpl*
PrfBasedKeyDerivationProtoKeySerializer() {
  static auto* serializer =
      new PrfBasedKeyDerivationProtoKeySerializerImpl(SerializeKey);
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

  status = registry.RegisterParametersSerializer(
      PrfBasedKeyDerivationProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(PrfBasedKeyDerivationProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(
      PrfBasedKeyDerivationProtoKeySerializer());
}

util::Status RegisterPrfBasedKeyDerivationProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  util::Status status = builder.RegisterParametersParser(
      PrfBasedKeyDerivationProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterParametersSerializer(
      PrfBasedKeyDerivationProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(PrfBasedKeyDerivationProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(
      PrfBasedKeyDerivationProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
