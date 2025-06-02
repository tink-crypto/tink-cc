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

#include "tink/aead/internal/aes_eax_proto_serialization_impl.h"

#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_eax_key.h"
#include "tink/aead/aes_eax_parameters.h"
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

using AesEaxProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, AesEaxParameters>;
using AesEaxProtoParametersSerializerImpl =
    ParametersSerializerImpl<AesEaxParameters, ProtoParametersSerialization>;
using AesEaxProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, AesEaxKey>;
using AesEaxProtoKeySerializerImpl =
    KeySerializerImpl<AesEaxKey, ProtoKeySerialization>;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesEaxKey";

struct AesEaxParamsStruct {
  uint32_t iv_size;

  static ProtoParser<AesEaxParamsStruct> CreateParser() {
    return ProtoParserBuilder<AesEaxParamsStruct>()
        .AddUint32Field(1, &AesEaxParamsStruct::iv_size)
        .BuildOrDie();
  }
};

struct AesEaxKeyFormatStruct {
  AesEaxParamsStruct params;
  uint32_t key_size;

  static const ProtoParser<AesEaxKeyFormatStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<AesEaxKeyFormatStruct>> parser{
        ProtoParserBuilder<AesEaxKeyFormatStruct>()
            .AddMessageField(1, &AesEaxKeyFormatStruct::params,
                             AesEaxParamsStruct::CreateParser())
            .AddUint32Field(2, &AesEaxKeyFormatStruct::key_size)
            .BuildOrDie()};
    return *parser;
  }
};

struct AesEaxKeyStruct {
  uint32_t version;
  AesEaxParamsStruct params;
  SecretData key_value;

  static const ProtoParser<AesEaxKeyStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<AesEaxKeyStruct>> parser{
        ProtoParserBuilder<AesEaxKeyStruct>()
            .AddUint32Field(1, &AesEaxKeyStruct::version)
            .AddMessageField(2, &AesEaxKeyStruct::params,
                             AesEaxParamsStruct::CreateParser())
            .AddBytesSecretDataField(3, &AesEaxKeyStruct::key_value)
            .BuildOrDie()};
    return *parser;
  }
};

absl::StatusOr<AesEaxParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixTypeEnum::kCrunchy:
      return AesEaxParameters::Variant::kCrunchy;
    case OutputPrefixTypeEnum::kRaw:
      return AesEaxParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return AesEaxParameters::Variant::kTink;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine AesEaxParameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    AesEaxParameters::Variant variant) {
  switch (variant) {
    case AesEaxParameters::Variant::kCrunchy:
      return OutputPrefixTypeEnum::kCrunchy;
    case AesEaxParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case AesEaxParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

absl::StatusOr<AesEaxParamsStruct> GetProtoParams(
    const AesEaxParameters& parameters) {
  // Legacy Tink AES-EAX key proto format assumes 16-byte tags.
  if (parameters.GetTagSizeInBytes() != 16) {
    return absl::InvalidArgumentError(
        "Tink currently restricts AES-EAX tag size to 16 bytes.");
  }

  AesEaxParamsStruct params{
      /*iv_size=*/static_cast<uint32_t>(parameters.GetIvSizeInBytes()),
  };
  return params;
}

absl::StatusOr<AesEaxParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const internal::KeyTemplateStruct& key_template =
      serialization.GetKeyTemplateStruct();
  if (key_template.type_url != kTypeUrl) {
    return absl::InvalidArgumentError(
        absl::StrCat("Wrong type URL when parsing AesEaxParameters: ",
                     key_template.type_url));
  }

  absl::StatusOr<AesEaxKeyFormatStruct> key_format_struct =
      AesEaxKeyFormatStruct::GetParser().Parse(key_template.value);
  if (!key_format_struct.ok()) {
    return absl::InvalidArgumentError("Failed to parse AesEaxKeyFormat proto");
  }

  absl::StatusOr<AesEaxParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplateStruct().output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  // Legacy Tink AES-EAX key proto format assumes 16-byte tags only.
  return AesEaxParameters::Builder()
      .SetVariant(*variant)
      .SetKeySizeInBytes(key_format_struct->key_size)
      .SetIvSizeInBytes(key_format_struct->params.iv_size)
      .SetTagSizeInBytes(16)
      .Build();
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const AesEaxParameters& parameters) {
  absl::StatusOr<AesEaxParamsStruct> params = GetProtoParams(parameters);
  if (!params.ok()) {
    return params.status();
  }

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  AesEaxKeyFormatStruct key_format_struct{
      /*params=*/*params,
      /*key_size=*/static_cast<uint32_t>(parameters.GetKeySizeInBytes())};
  absl::StatusOr<std::string> serialized_proto =
      AesEaxKeyFormatStruct::GetParser().SerializeIntoString(key_format_struct);
  if (!serialized_proto.ok()) {
    return serialized_proto.status();
  }

  return ProtoParametersSerialization::Create(kTypeUrl, *output_prefix_type,
                                              *serialized_proto);
}

absl::StatusOr<AesEaxKey> ParseKey(const ProtoKeySerialization& serialization,
                                   absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesEaxKey.");
  }
  if (!token.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }

  absl::StatusOr<AesEaxKeyStruct> key_struct =
      AesEaxKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!key_struct.ok()) {
    return absl::InvalidArgumentError("Failed to parse AesEaxKey proto");
  }
  if (key_struct->version != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<AesEaxParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixTypeEnum());
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetVariant(*variant)
          .SetKeySizeInBytes(key_struct->key_value.size())
          .SetIvSizeInBytes(key_struct->params.iv_size)
          // Legacy AES-EAX key proto format assumes 16-byte tags.
          .SetTagSizeInBytes(16)
          .Build();
  if (!parameters.ok()) return parameters.status();

  return AesEaxKey::Create(
      *parameters, RestrictedData(std::move(key_struct->key_value), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const AesEaxKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<AesEaxParamsStruct> params =
      GetProtoParams(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  absl::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) return restricted_input.status();
  if (!token.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }

  AesEaxKeyStruct key_struct{/*version=*/0,
                             /*params=*/*params,
                             /*key_value=*/restricted_input->Get(*token)};
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  absl::StatusOr<SecretData> serialized_proto =
      AesEaxKeyStruct::GetParser().SerializeIntoSecretData(key_struct);
  if (!serialized_proto.ok()) {
    return serialized_proto.status();
  }
  return ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(*std::move(serialized_proto), *token),
      KeyMaterialTypeEnum::kSymmetric, *output_prefix_type,
      key.GetIdRequirement());
}

AesEaxProtoParametersParserImpl* AesEaxProtoParametersParser() {
  static auto* parser =
      new AesEaxProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

AesEaxProtoParametersSerializerImpl* AesEaxProtoParametersSerializer() {
  static auto* serializer =
      new AesEaxProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

AesEaxProtoKeyParserImpl* AesEaxProtoKeyParser() {
  static auto* parser = new AesEaxProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesEaxProtoKeySerializerImpl* AesEaxProtoKeySerializer() {
  static auto* serializer = new AesEaxProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterAesEaxProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(AesEaxProtoParametersParser());
  if (!status.ok()) return status;

  status =
      registry.RegisterParametersSerializer(AesEaxProtoParametersSerializer());
  if (!status.ok()) return status;

  status = registry.RegisterKeyParser(AesEaxProtoKeyParser());
  if (!status.ok()) return status;

  return registry.RegisterKeySerializer(AesEaxProtoKeySerializer());
}

absl::Status RegisterAesEaxProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(AesEaxProtoParametersParser());
  if (!status.ok()) return status;

  status =
      builder.RegisterParametersSerializer(AesEaxProtoParametersSerializer());
  if (!status.ok()) return status;

  status = builder.RegisterKeyParser(AesEaxProtoKeyParser());
  if (!status.ok()) return status;

  return builder.RegisterKeySerializer(AesEaxProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
