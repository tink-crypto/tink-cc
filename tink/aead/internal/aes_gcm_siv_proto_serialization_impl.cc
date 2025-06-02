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

#include "tink/aead/internal/aes_gcm_siv_proto_serialization_impl.h"

#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_siv_key.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
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
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;

using AesGcmSivProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, AesGcmSivParameters>;
using AesGcmSivProtoParametersSerializerImpl =
    ParametersSerializerImpl<AesGcmSivParameters, ProtoParametersSerialization>;
using AesGcmSivProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, AesGcmSivKey>;
using AesGcmSivProtoKeySerializerImpl =
    KeySerializerImpl<AesGcmSivKey, ProtoKeySerialization>;

struct AesGcmSivKeyFormatStruct {
  uint32_t version;
  uint32_t key_size;

  static const ProtoParser<AesGcmSivKeyFormatStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<AesGcmSivKeyFormatStruct>>
        parser{ProtoParserBuilder<AesGcmSivKeyFormatStruct>()
                   .AddUint32Field(1, &AesGcmSivKeyFormatStruct::version)
                   .AddUint32Field(2, &AesGcmSivKeyFormatStruct::key_size)
                   .BuildOrDie()};
    return *parser;
  }
};

struct AesGcmSivKeyStruct {
  uint32_t version;
  SecretData key_value;

  static const ProtoParser<AesGcmSivKeyStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<AesGcmSivKeyStruct>> parser{
        ProtoParserBuilder<AesGcmSivKeyStruct>()
            .AddUint32Field(1, &AesGcmSivKeyStruct::version)
            .AddBytesSecretDataField(3, &AesGcmSivKeyStruct::key_value)
            .BuildOrDie()};
    return *parser;
  }
};

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesGcmSivKey";

absl::StatusOr<AesGcmSivParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixTypeEnum::kCrunchy:
      return AesGcmSivParameters::Variant::kCrunchy;
    case OutputPrefixTypeEnum::kRaw:
      return AesGcmSivParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return AesGcmSivParameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine AesGcmSivParameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    AesGcmSivParameters::Variant variant) {
  switch (variant) {
    case AesGcmSivParameters::Variant::kCrunchy:
      return OutputPrefixTypeEnum::kCrunchy;
    case AesGcmSivParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case AesGcmSivParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

absl::StatusOr<AesGcmSivParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const internal::KeyTemplateStruct& key_template =
      serialization.GetKeyTemplateStruct();
  if (key_template.type_url != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesGcmSivParameters.");
  }

  absl::StatusOr<AesGcmSivKeyFormatStruct> key_format =
      AesGcmSivKeyFormatStruct::GetParser().Parse(key_template.value);
  if (!key_format.ok()) {
    return absl::InvalidArgumentError(
        "Failed to parse AesGcmSivKeyFormat proto");
  }
  if (key_format->version != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<AesGcmSivParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplateStruct().output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }
  return AesGcmSivParameters::Create(key_format->key_size, *variant);
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const AesGcmSivParameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  AesGcmSivKeyFormatStruct key_format{
      /*version=*/0,
      /*key_size=*/static_cast<uint32_t>(parameters.KeySizeInBytes())};
  absl::StatusOr<std::string> serialized_key_format =
      AesGcmSivKeyFormatStruct::GetParser().SerializeIntoString(key_format);
  if (!serialized_key_format.ok()) {
    return serialized_key_format.status();
  }

  return ProtoParametersSerialization::Create(kTypeUrl, *output_prefix_type,
                                              *serialized_key_format);
}

absl::StatusOr<AesGcmSivKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesGcmSivKey.");
  }

  absl::StatusOr<AesGcmSivKeyStruct> key_struct =
      AesGcmSivKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!key_struct.ok()) {
    return absl::InvalidArgumentError("Failed to parse AesGcmSivKey proto");
  }
  if (key_struct->version != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<AesGcmSivParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixTypeEnum());
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<AesGcmSivParameters> parameters =
      AesGcmSivParameters::Create(key_struct->key_value.size(), *variant);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return AesGcmSivKey::Create(
      *parameters, RestrictedData(std::move(key_struct->key_value), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const AesGcmSivKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  absl::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  AesGcmSivKeyStruct key_struct{
      /*version=*/0,
      /*key_value=*/restricted_input->Get(*token),
  };

  absl::StatusOr<SecretData> serialized_key =
      AesGcmSivKeyStruct::GetParser().SerializeIntoSecretData(key_struct);
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output =
      RestrictedData(*std::move(serialized_key), *token);
  return ProtoKeySerialization::Create(
      kTypeUrl, std::move(restricted_output), KeyMaterialTypeEnum::kSymmetric,
      *output_prefix_type, key.GetIdRequirement());
}

AesGcmSivProtoParametersParserImpl* AesGcmSivProtoParametersParser() {
  static auto* parser =
      new AesGcmSivProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

AesGcmSivProtoParametersSerializerImpl* AesGcmSivProtoParametersSerializer() {
  static auto* serializer =
      new AesGcmSivProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

AesGcmSivProtoKeyParserImpl* AesGcmSivProtoKeyParser() {
  static auto* parser = new AesGcmSivProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesGcmSivProtoKeySerializerImpl* AesGcmSivProtoKeySerializer() {
  static auto* serializer = new AesGcmSivProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterAesGcmSivProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(AesGcmSivProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      AesGcmSivProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(AesGcmSivProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(AesGcmSivProtoKeySerializer());
}

absl::Status RegisterAesGcmSivProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(AesGcmSivProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterParametersSerializer(
      AesGcmSivProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(AesGcmSivProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(AesGcmSivProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
