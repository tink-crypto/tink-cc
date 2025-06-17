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
#include "tink/streamingaead/internal/aes_gcm_hkdf_streaming_proto_serialization_impl.h"

#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
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
#include "tink/internal/proto_parser.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

struct AesGcmHkdfStreamingParamsStruct {
  uint32_t ciphertext_segment_size;
  uint32_t derived_key_size;
  HashTypeEnum hkdf_hash_type;

  static ProtoParser<AesGcmHkdfStreamingParamsStruct> CreateParser() {
    return ProtoParserBuilder<AesGcmHkdfStreamingParamsStruct>()
        .AddUint32Field(
            1, &AesGcmHkdfStreamingParamsStruct::ciphertext_segment_size)
        .AddUint32Field(2, &AesGcmHkdfStreamingParamsStruct::derived_key_size)
        .AddEnumField(3, &AesGcmHkdfStreamingParamsStruct::hkdf_hash_type,
                      &HashTypeEnumIsValid)
        .BuildOrDie();
  }
};

struct AesGcmHkdfStreamingKeyFormatStruct {
  uint32_t version;
  AesGcmHkdfStreamingParamsStruct params;
  uint32_t key_size;

  static ProtoParser<AesGcmHkdfStreamingKeyFormatStruct> CreateParser() {
    return ProtoParserBuilder<AesGcmHkdfStreamingKeyFormatStruct>()
        .AddMessageField(1, &AesGcmHkdfStreamingKeyFormatStruct::params,
                         AesGcmHkdfStreamingParamsStruct::CreateParser())
        .AddUint32Field(2, &AesGcmHkdfStreamingKeyFormatStruct::key_size)
        .AddUint32Field(3, &AesGcmHkdfStreamingKeyFormatStruct::version)
        .BuildOrDie();
  }

  static const ProtoParser<AesGcmHkdfStreamingKeyFormatStruct>& Parser() {
    static absl::NoDestructor<ProtoParser<AesGcmHkdfStreamingKeyFormatStruct>>
        parser{AesGcmHkdfStreamingKeyFormatStruct::CreateParser()};
    return *parser;
  }
};

struct AesGcmHkdfStreamingKeyStruct {
  uint32_t version;
  AesGcmHkdfStreamingParamsStruct params;
  SecretData key_value;

  static ProtoParser<AesGcmHkdfStreamingKeyStruct> CreateParser() {
    return ProtoParserBuilder<AesGcmHkdfStreamingKeyStruct>()
        .AddUint32Field(1, &AesGcmHkdfStreamingKeyStruct::version)
        .AddMessageField(2, &AesGcmHkdfStreamingKeyStruct::params,
                         AesGcmHkdfStreamingParamsStruct::CreateParser())
        .AddBytesSecretDataField(3, &AesGcmHkdfStreamingKeyStruct::key_value)
        .BuildOrDie();
  }

  static const ProtoParser<AesGcmHkdfStreamingKeyStruct>& Parser() {
    static absl::NoDestructor<ProtoParser<AesGcmHkdfStreamingKeyStruct>> parser{
        AesGcmHkdfStreamingKeyStruct::CreateParser()};
    return *parser;
  }
};

using AesGcmHkdfStreamingProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization,
                         AesGcmHkdfStreamingParameters>;
using AesGcmHkdfStreamingProtoParametersSerializerImpl =
    ParametersSerializerImpl<AesGcmHkdfStreamingParameters,
                             ProtoParametersSerialization>;
using AesGcmHkdfStreamingProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, AesGcmHkdfStreamingKey>;
using AesGcmHkdfStreamingProtoKeySerializerImpl =
    KeySerializerImpl<AesGcmHkdfStreamingKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

absl::StatusOr<AesGcmHkdfStreamingParameters::HashType> FromProtoHashType(
    HashTypeEnum hash_type) {
  switch (hash_type) {
    case HashTypeEnum::kSha1:
      return AesGcmHkdfStreamingParameters::HashType::kSha1;
    case HashTypeEnum::kSha256:
      return AesGcmHkdfStreamingParameters::HashType::kSha256;
    case HashTypeEnum::kSha512:
      return AesGcmHkdfStreamingParameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("Unsupported proto hash type: ", hash_type));
  }
}

absl::StatusOr<HashTypeEnum> ToProtoHashType(
    AesGcmHkdfStreamingParameters::HashType hash_type) {
  switch (hash_type) {
    case AesGcmHkdfStreamingParameters::HashType::kSha1:
      return HashTypeEnum::kSha1;
    case AesGcmHkdfStreamingParameters::HashType::kSha256:
      return HashTypeEnum::kSha256;
    case AesGcmHkdfStreamingParameters::HashType::kSha512:
      return HashTypeEnum::kSha512;
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("Unsupported hash type: ", hash_type));
  }
}

absl::StatusOr<AesGcmHkdfStreamingParameters> ToParameters(
    const AesGcmHkdfStreamingParamsStruct& params, int key_size) {
  absl::StatusOr<AesGcmHkdfStreamingParameters::HashType> hash_type =
      FromProtoHashType(params.hkdf_hash_type);
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  return AesGcmHkdfStreamingParameters::Builder()
      .SetKeySizeInBytes(key_size)
      .SetDerivedKeySizeInBytes(params.derived_key_size)
      .SetHashType(*hash_type)
      .SetCiphertextSegmentSizeInBytes(params.ciphertext_segment_size)
      .Build();
}

absl::StatusOr<AesGcmHkdfStreamingParamsStruct> FromParameters(
    const AesGcmHkdfStreamingParameters& parameters) {
  absl::StatusOr<HashTypeEnum> hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  AesGcmHkdfStreamingParamsStruct params;
  params.derived_key_size = parameters.DerivedKeySizeInBytes();
  params.hkdf_hash_type = *hash_type;
  params.ciphertext_segment_size = parameters.CiphertextSegmentSizeInBytes();
  return params;
}

absl::StatusOr<AesGcmHkdfStreamingParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateStruct& key_template = serialization.GetKeyTemplateStruct();
  if (key_template.type_url != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesGcmHkdfStreamingParameters.");
  }
  absl::StatusOr<AesGcmHkdfStreamingKeyFormatStruct> parsed_key_format =
      AesGcmHkdfStreamingKeyFormatStruct::Parser().Parse(key_template.value);
  if (!parsed_key_format.ok()) {
    return parsed_key_format.status();
  }

  if (parsed_key_format->version != 0) {
    return absl::InvalidArgumentError(
        "Parsing AesGcmHkdfStreamingKeyFormat failed: only "
        "version 0 is accepted.");
  }

  return ToParameters(parsed_key_format->params, parsed_key_format->key_size);
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const AesGcmHkdfStreamingParameters& parameters) {
  absl::StatusOr<AesGcmHkdfStreamingParamsStruct> params_struct =
      FromParameters(parameters);
  if (!params_struct.ok()) {
    return params_struct.status();
  }
  AesGcmHkdfStreamingKeyFormatStruct format;
  format.version = 0;
  format.key_size = parameters.KeySizeInBytes();
  format.params = *params_struct;

  absl::StatusOr<std::string> serialized =
      AesGcmHkdfStreamingKeyFormatStruct::Parser().SerializeIntoString(format);
  if (!serialized.ok()) {
    return serialized.status();
  }
  return ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixTypeEnum::kRaw, *serialized);
}

absl::StatusOr<AesGcmHkdfStreamingKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesGcmHkdfStreamingKey.");
  }

  absl::StatusOr<AesGcmHkdfStreamingKeyStruct> parsed_key =
      AesGcmHkdfStreamingKeyStruct::Parser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!parsed_key.ok()) {
    return parsed_key.status();
  }

  if (parsed_key->version != 0) {
    return absl::InvalidArgumentError(
        "Parsing AesGcmHkdfStreamingKey failed: only version 0 is accepted.");
  }

  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      ToParameters(parsed_key->params, parsed_key->key_value.size());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return AesGcmHkdfStreamingKey::Create(
      *parameters, RestrictedData(std::move(parsed_key->key_value), *token),
      GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const AesGcmHkdfStreamingKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  absl::StatusOr<RestrictedData> initial_key_material =
      key.GetInitialKeyMaterial(GetPartialKeyAccess());
  if (!initial_key_material.ok()) {
    return initial_key_material.status();
  }

  absl::StatusOr<AesGcmHkdfStreamingParamsStruct> params_struct =
      FromParameters(key.GetParameters());
  if (!params_struct.ok()) {
    return params_struct.status();
  }
  AesGcmHkdfStreamingKeyStruct key_struct;
  key_struct.version = 0;
  key_struct.params = *params_struct;
  key_struct.key_value =
      util::SecretDataFromStringView(initial_key_material->GetSecret(*token));

  absl::StatusOr<SecretData> serialized_key =
      AesGcmHkdfStreamingKeyStruct::Parser().SerializeIntoSecretData(
          key_struct);
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  return ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(*std::move(serialized_key), *token),
      KeyMaterialTypeEnum::kSymmetric, OutputPrefixTypeEnum::kRaw,
      key.GetIdRequirement());
}

AesGcmHkdfStreamingProtoParametersParserImpl*
AesGcmHkdfStreamingProtoParametersParser() {
  static auto* parser = new AesGcmHkdfStreamingProtoParametersParserImpl(
      kTypeUrl, ParseParameters);
  return parser;
}

AesGcmHkdfStreamingProtoParametersSerializerImpl*
AesGcmHkdfStreamingProtoParametersSerializer() {
  static auto* serializer =
      new AesGcmHkdfStreamingProtoParametersSerializerImpl(kTypeUrl,
                                                           SerializeParameters);
  return serializer;
}

AesGcmHkdfStreamingProtoKeyParserImpl* AesGcmHkdfStreamingProtoKeyParser() {
  static auto* parser =
      new AesGcmHkdfStreamingProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesGcmHkdfStreamingProtoKeySerializerImpl*
AesGcmHkdfStreamingProtoKeySerializer() {
  static auto* serializer =
      new AesGcmHkdfStreamingProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterAesGcmHkdfStreamingProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status = registry.RegisterParametersParser(
      AesGcmHkdfStreamingProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      AesGcmHkdfStreamingProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(AesGcmHkdfStreamingProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(
      AesGcmHkdfStreamingProtoKeySerializer());
}

absl::Status RegisterAesGcmHkdfStreamingProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status = builder.RegisterParametersParser(
      AesGcmHkdfStreamingProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterParametersSerializer(
      AesGcmHkdfStreamingProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(AesGcmHkdfStreamingProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(AesGcmHkdfStreamingProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
