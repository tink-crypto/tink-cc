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

#include "tink/mac/internal/hmac_proto_serialization_impl.h"

#include <array>
#include <cstdint>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/common_proto_enums.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/mac/hmac_key.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/mac/internal/hmac_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using HmacProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, HmacParameters>;
using HmacProtoParametersSerializerImpl =
    ParametersSerializerImpl<HmacParameters, ProtoParametersSerialization>;
using HmacProtoKeyParserImpl = KeyParserImpl<ProtoKeySerialization, HmacKey>;
using HmacProtoKeySerializerImpl =
    KeySerializerImpl<HmacKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.HmacKey";

absl::StatusOr<HmacParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kCrunchy:
      return HmacParameters::Variant::kCrunchy;
    case OutputPrefixTypeEnum::kLegacy:
      return HmacParameters::Variant::kLegacy;
    case OutputPrefixTypeEnum::kRaw:
      return HmacParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return HmacParameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine HmacParameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    HmacParameters::Variant variant) {
  switch (variant) {
    case HmacParameters::Variant::kCrunchy:
      return OutputPrefixTypeEnum::kCrunchy;
    case HmacParameters::Variant::kLegacy:
      return OutputPrefixTypeEnum::kLegacy;
    case HmacParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case HmacParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

absl::StatusOr<HmacParameters::HashType> ToHashType(HashTypeEnum hash_type) {
  switch (hash_type) {
    case HashTypeEnum::kSha1:
      return HmacParameters::HashType::kSha1;
    case HashTypeEnum::kSha224:
      return HmacParameters::HashType::kSha224;
    case HashTypeEnum::kSha256:
      return HmacParameters::HashType::kSha256;
    case HashTypeEnum::kSha384:
      return HmacParameters::HashType::kSha384;
    case HashTypeEnum::kSha512:
      return HmacParameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError("Could not determine HashType");
  }
}

absl::StatusOr<HashTypeEnum> ToProtoHashType(
    HmacParameters::HashType hash_type) {
  switch (hash_type) {
    case HmacParameters::HashType::kSha1:
      return HashTypeEnum::kSha1;
    case HmacParameters::HashType::kSha224:
      return HashTypeEnum::kSha224;
    case HmacParameters::HashType::kSha256:
      return HashTypeEnum::kSha256;
    case HmacParameters::HashType::kSha384:
      return HashTypeEnum::kSha384;
    case HmacParameters::HashType::kSha512:
      return HashTypeEnum::kSha512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine HmacParameters::HashType");
  }
}

absl::StatusOr<HmacParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateStruct key_template = serialization.GetKeyTemplateStruct();
  if (key_template.type_url != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing HmacParameters.");
  }

  ProtoHmacKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value)) {
    return absl::InvalidArgumentError("Failed to parse HmacKeyFormat proto.");
  }
  if (proto_key_format.version() != 0) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing HmacParameters failed: only version 0 is accepted");
  }

  absl::StatusOr<HmacParameters::Variant> variant =
      ToVariant(key_template.output_prefix_type);
  if (!variant.ok()) return variant.status();

  absl::StatusOr<HmacParameters::HashType> hash_type =
      ToHashType(proto_key_format.params().hash());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  return HmacParameters::Create(proto_key_format.key_size(),
                                proto_key_format.params().tag_size(),
                                *hash_type, *variant);
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const HmacParameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();
  absl::StatusOr<HashTypeEnum> proto_hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!proto_hash_type.ok()) return proto_hash_type.status();

  ProtoHmacKeyFormat proto_key_format;
  proto_key_format.mutable_params()->set_hash(*proto_hash_type);
  proto_key_format.mutable_params()->set_tag_size(
      parameters.CryptographicTagSizeInBytes());
  proto_key_format.set_key_size(parameters.KeySizeInBytes());
  proto_key_format.set_version(0);

  return ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

absl::StatusOr<HmacKey> ParseKey(const ProtoKeySerialization& serialization,
                                 absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError("Wrong type URL when parsing HmacKey.");
  }
  if (!token.has_value()) {
    return absl::InvalidArgumentError("SecretKeyAccess is required");
  }

  ProtoHmacKey proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse HmacKey proto.");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<HmacParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixTypeEnum());
  if (!variant.ok()) return variant.status();
  absl::StatusOr<HmacParameters::HashType> hash_type =
      ToHashType(proto_key.params().hash());
  if (!hash_type.ok()) return hash_type.status();

  absl::StatusOr<HmacParameters> parameters = HmacParameters::Create(
      proto_key.key_value().size(), proto_key.params().tag_size(), *hash_type,
      *variant);
  if (!parameters.ok()) return parameters.status();

  return HmacKey::Create(
      *parameters, RestrictedData(std::move(proto_key.key_value()), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const HmacKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!token.has_value()) {
    return absl::InvalidArgumentError("SecretKeyAccess is required");
  }
  if (!restricted_input.ok()) return restricted_input.status();
  absl::StatusOr<HashTypeEnum> proto_hash_type =
      ToProtoHashType(key.GetParameters().GetHashType());
  if (!proto_hash_type.ok()) return proto_hash_type.status();

  ProtoHmacKey proto_key;
  proto_key.mutable_params()->set_hash(*proto_hash_type);
  proto_key.mutable_params()->set_tag_size(
      key.GetParameters().CryptographicTagSizeInBytes());
  proto_key.set_version(0);
  proto_key.set_key_value(restricted_input->GetSecret(*token));

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  SecretData serialized_key = proto_key.SerializeAsSecretData();
  RestrictedData restricted_output =
      RestrictedData(std::move(serialized_key), *token);
  return ProtoKeySerialization::Create(
      kTypeUrl, std::move(restricted_output), KeyMaterialTypeEnum::kSymmetric,
      *output_prefix_type, key.GetIdRequirement());
}

HmacProtoParametersParserImpl* HmacProtoParametersParser() {
  static auto* parser =
      new HmacProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

HmacProtoParametersSerializerImpl* HmacProtoParametersSerializer() {
  static auto* serializer =
      new HmacProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

HmacProtoKeyParserImpl* HmacProtoKeyParser() {
  static auto* parser = new HmacProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

HmacProtoKeySerializerImpl* HmacProtoKeySerializer() {
  static auto* serializer = new HmacProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterHmacProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(HmacProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      registry.RegisterParametersSerializer(HmacProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(HmacProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(HmacProtoKeySerializer());
}

absl::Status RegisterHmacProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(HmacProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      builder.RegisterParametersSerializer(HmacProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(HmacProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(HmacProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
