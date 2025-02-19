// Copyright 2024 Google LLC
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

#include "tink/aead/internal/legacy_kms_aead_proto_serialization_impl.h"

#include <cstdint>
#include <string>

#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/legacy_kms_aead_key.h"
#include "tink/aead/legacy_kms_aead_parameters.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/proto_parser.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;
using ::crypto::tink::util::SecretData;

using LegacyKmsAeadProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   LegacyKmsAeadParameters>;
using LegacyKmsAeadProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<LegacyKmsAeadParameters,
                                       internal::ProtoParametersSerialization>;
using LegacyKmsAeadProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, LegacyKmsAeadKey>;
using LegacyKmsAeadProtoKeySerializerImpl =
    internal::KeySerializerImpl<LegacyKmsAeadKey,
                                internal::ProtoKeySerialization>;

struct KmsAeadKeyFormatStruct {
  std::string key_uri;

  static ProtoParser<KmsAeadKeyFormatStruct> CreateParser() {
    return ProtoParserBuilder<KmsAeadKeyFormatStruct>()
        .AddBytesStringField(1, &KmsAeadKeyFormatStruct::key_uri)
        .BuildOrDie();
  }

  static const ProtoParser<KmsAeadKeyFormatStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<KmsAeadKeyFormatStruct>> parser(
        CreateParser());
    return *parser;
  }
};

struct KmsAeadKeyStruct {
  uint32_t version;
  KmsAeadKeyFormatStruct params;

  static const ProtoParser<KmsAeadKeyStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<KmsAeadKeyStruct>> parser(
        ProtoParserBuilder<KmsAeadKeyStruct>()
            .AddUint32Field(1, &KmsAeadKeyStruct::version)
            .AddMessageField(2, &KmsAeadKeyStruct::params,
                             KmsAeadKeyFormatStruct::CreateParser())
            .BuildOrDie());
    return *parser;
  }
};

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.KmsAeadKey";

absl::StatusOr<LegacyKmsAeadParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kRaw:
      return LegacyKmsAeadParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return LegacyKmsAeadParameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine LegacyKmsAeadParameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    LegacyKmsAeadParameters::Variant variant) {
  switch (variant) {
    case LegacyKmsAeadParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case LegacyKmsAeadParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

absl::StatusOr<LegacyKmsAeadParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  const KeyTemplateStruct key_template = serialization.GetKeyTemplateStruct();
  if (key_template.type_url != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing LegacyKmsAeadParameters.");
  }
  absl::StatusOr<KmsAeadKeyFormatStruct> key_format =
      KmsAeadKeyFormatStruct::GetParser().Parse(key_template.value);
  if (!key_format.ok()) {
    return key_format.status();
  }
  absl::StatusOr<LegacyKmsAeadParameters::Variant> variant =
      ToVariant(key_template.output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }
  return LegacyKmsAeadParameters::Create(key_format->key_uri, *variant);
}

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const LegacyKmsAeadParameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  KmsAeadKeyFormatStruct key_format;
  key_format.key_uri = parameters.GetKeyUri();

  absl::StatusOr<std::string> serialized_key_format =
      KmsAeadKeyFormatStruct::GetParser().SerializeIntoString(key_format);
  if (!serialized_key_format.ok()) {
    return serialized_key_format.status();
  }

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, *serialized_key_format);
}

absl::StatusOr<LegacyKmsAeadKey> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing LegacyKmsAeadKey.");
  }
  absl::StatusOr<KmsAeadKeyStruct> proto_key =
      KmsAeadKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(
              GetInsecureSecretKeyAccessInternal()));
  if (!proto_key.ok()) {
    return proto_key.status();
  }
  if (proto_key->version != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<LegacyKmsAeadParameters::Variant> variant = ToVariant(
      static_cast<OutputPrefixTypeEnum>(serialization.GetOutputPrefixType()));
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(proto_key->params.key_uri, *variant);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return LegacyKmsAeadKey::Create(*parameters, serialization.IdRequirement());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const LegacyKmsAeadKey& key, absl::optional<SecretKeyAccessToken> token) {
  KmsAeadKeyStruct proto_key;
  proto_key.version = 0;
  proto_key.params = {/*key_uri=*/key.GetParameters().GetKeyUri()};

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<SecretData> serialized_key =
      KmsAeadKeyStruct::GetParser().SerializeIntoSecretData(proto_key);
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }

  RestrictedData restricted_output =
      RestrictedData(*serialized_key, GetInsecureSecretKeyAccessInternal());

  return internal::ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, KeyMaterialTypeEnum::kRemote,
      *output_prefix_type, key.GetIdRequirement());
}

LegacyKmsAeadProtoParametersParserImpl* LegacyKmsAeadProtoParametersParser() {
  static auto* parser =
      new LegacyKmsAeadProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

LegacyKmsAeadProtoParametersSerializerImpl*
LegacyKmsAeadProtoParametersSerializer() {
  static auto* serializer = new LegacyKmsAeadProtoParametersSerializerImpl(
      kTypeUrl, SerializeParameters);
  return serializer;
}

LegacyKmsAeadProtoKeyParserImpl* LegacyKmsAeadProtoKeyParser() {
  static auto* parser = new LegacyKmsAeadProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

LegacyKmsAeadProtoKeySerializerImpl* LegacyKmsAeadProtoKeySerializer() {
  static auto* serializer =
      new LegacyKmsAeadProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterLegacyKmsAeadProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(LegacyKmsAeadProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      LegacyKmsAeadProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(LegacyKmsAeadProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(LegacyKmsAeadProtoKeySerializer());
}

absl::Status RegisterLegacyKmsAeadProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(LegacyKmsAeadProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterParametersSerializer(
      LegacyKmsAeadProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(LegacyKmsAeadProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(LegacyKmsAeadProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
