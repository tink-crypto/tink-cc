// Copyright 2023 Google LLC
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

#include "tink/hybrid/internal/hpke_proto_serialization_impl.h"

#include <array>
#include <cstdint>
#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid/internal/hpke_proto_structs.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"
#include "proto/hpke.tinkpb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::google::crypto::tink::internal::HpkeKeyFormatTP;
using ::google::crypto::tink::internal::HpkeParamsTP;
using ::google::crypto::tink::internal::HpkePrivateKeyTP;
using ::google::crypto::tink::internal::HpkePublicKeyTP;

using HpkeProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, HpkeParameters>;
using HpkeProtoParametersSerializerImpl =
    ParametersSerializerImpl<HpkeParameters, ProtoParametersSerialization>;
using HpkeProtoPublicKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, HpkePublicKey>;
using HpkeProtoPublicKeySerializerImpl =
    KeySerializerImpl<HpkePublicKey, ProtoKeySerialization>;
using HpkeProtoPrivateKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, HpkePrivateKey>;
using HpkeProtoPrivateKeySerializerImpl =
    KeySerializerImpl<HpkePrivateKey, ProtoKeySerialization>;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.HpkePublicKey";
const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.HpkePrivateKey";

absl::StatusOr<HpkeParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const google::crypto::tink::internal::KeyTemplateTP& key_template =
      serialization.GetKeyTemplate();
  if (key_template.type_url() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing HpkeParameters.");
  }

  HpkeKeyFormatTP proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError("Failed to parse HpkeKeyFormat proto");
  }

  return HpkeParametersFromProto(key_template.output_prefix_type(),
                      proto_key_format.params());
}

absl::StatusOr<HpkePublicKey> ParsePublicKey(
    const ProtoKeySerialization& serialization,
    std::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing HpkePublicKey.");
  }

  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  HpkePublicKeyTP proto_key;
  if (!proto_key.ParseFromString(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()))) {
    return absl::InvalidArgumentError("Failed to parse HpkePublicKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<HpkeParameters> parameters = HpkeParametersFromProto(
      serialization.GetOutputPrefixTypeTP(), proto_key.params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return HpkePublicKey::Create(*parameters, proto_key.public_key(),
                               serialization.IdRequirement(),
                               GetPartialKeyAccess());
}

absl::StatusOr<HpkePrivateKey> ParsePrivateKey(
    const ProtoKeySerialization& serialization,
    std::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing HpkePrivateKey.");
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  HpkePrivateKeyTP proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse HpkePrivateKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  if (proto_key.public_key().version() != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 public keys are accepted.");
  }

  absl::StatusOr<HpkeParameters> parameters = HpkeParametersFromProto(
      serialization.GetOutputPrefixTypeTP(), proto_key.public_key().params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, proto_key.public_key().public_key(),
      serialization.IdRequirement(), GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return HpkePrivateKey::Create(*public_key,
                                RestrictedData(proto_key.private_key(), *token),
                                GetPartialKeyAccess());
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const HpkeParameters& parameters) {
  absl::StatusOr<google::crypto::tink::internal::OutputPrefixTypeTP>
      output_prefix_type =
          HpkeVariantToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<HpkeParamsTP> params = HpkeParamsToProto(parameters);
  if (!params.ok()) {
    return params.status();
  }
  HpkeKeyFormatTP proto_key_format;
  *proto_key_format.mutable_params() = *params;

  return ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type,
      proto_key_format.SerializeAsString());
}

absl::StatusOr<ProtoKeySerialization> SerializePublicKey(
    const HpkePublicKey& key, std::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<HpkeParamsTP> params = HpkeParamsToProto(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  HpkePublicKeyTP proto_key;
  proto_key.set_version(0);
  *proto_key.mutable_params() = *params;
  proto_key.set_public_key(key.GetPublicKeyBytes(GetPartialKeyAccess()));

  absl::StatusOr<google::crypto::tink::internal::OutputPrefixTypeTP>
      output_prefix_type =
          HpkeVariantToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output = RestrictedData(
      proto_key.SerializeAsString(), InsecureSecretKeyAccess::Get());
  return ProtoKeySerialization::Create(
      kPublicTypeUrl, restricted_output,
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPublic,
      *output_prefix_type, key.GetIdRequirement());
}

absl::StatusOr<ProtoKeySerialization> SerializePrivateKey(
    const HpkePrivateKey& key, std::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetPrivateKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  absl::StatusOr<HpkeParamsTP> params = HpkeParamsToProto(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  HpkePrivateKeyTP proto_key;
  proto_key.mutable_public_key()->set_version(0);
  *proto_key.mutable_public_key()->mutable_params() = *params;
  proto_key.mutable_public_key()->set_public_key(
      key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess()));
  proto_key.set_version(0);
  proto_key.set_private_key(restricted_input->Get(*token));

  absl::StatusOr<google::crypto::tink::internal::OutputPrefixTypeTP>
      output_prefix_type = HpkeVariantToOutputPrefixType(
          key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return ProtoKeySerialization::Create(
      kPrivateTypeUrl,
      RestrictedData(proto_key.SerializeAsSecretData(), *token),
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPrivate,
      *output_prefix_type, key.GetIdRequirement());
}

HpkeProtoParametersParserImpl* HpkeProtoParametersParser() {
  static auto* parser =
      new HpkeProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return parser;
}

HpkeProtoParametersSerializerImpl* HpkeProtoParametersSerializer() {
  static auto* serializer = new HpkeProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return serializer;
}

HpkeProtoPublicKeyParserImpl* HpkeProtoPublicKeyParser() {
  static auto* parser =
      new HpkeProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return parser;
}

HpkeProtoPublicKeySerializerImpl* HpkeProtoPublicKeySerializer() {
  static auto* serializer =
      new HpkeProtoPublicKeySerializerImpl(SerializePublicKey);
  return serializer;
}

HpkeProtoPrivateKeyParserImpl* HpkeProtoPrivateKeyParser() {
  static auto* parser =
      new HpkeProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return parser;
}

HpkeProtoPrivateKeySerializerImpl* HpkeProtoPrivateKeySerializer() {
  static auto* serializer =
      new HpkeProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return serializer;
}

}  // namespace

absl::Status RegisterHpkeProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(HpkeProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      registry.RegisterParametersSerializer(HpkeProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(HpkeProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeySerializer(HpkeProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(HpkeProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(HpkeProtoPrivateKeySerializer());
}

absl::Status RegisterHpkeProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(HpkeProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      builder.RegisterParametersSerializer(HpkeProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(HpkeProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeySerializer(HpkeProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(HpkeProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(HpkeProtoPrivateKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
