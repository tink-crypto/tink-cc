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

#include "tink/streamingaead/internal/aes_ctr_hmac_streaming_proto_serialization_impl.h"

#include <sys/types.h>

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
#include "tink/streamingaead/aes_ctr_hmac_streaming_key.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

struct HmacParamsStruct {
  HashTypeEnum hash;
  uint32_t tag_size;

  static ProtoParser<HmacParamsStruct> CreateParser() {
    return ProtoParserBuilder<HmacParamsStruct>()
        .AddEnumField(1, &HmacParamsStruct::hash, &HashTypeEnumIsValid)
        .AddUint32Field(2, &HmacParamsStruct::tag_size)
        .BuildOrDie();
  }
};

struct AesCtrHmacStreamingParamsStruct {
  uint32_t ciphertext_segment_size;
  uint32_t derived_key_size;
  HashTypeEnum hkdf_hash_type;
  HmacParamsStruct hmac_params;

  static ProtoParser<AesCtrHmacStreamingParamsStruct> CreateParser() {
    return ProtoParserBuilder<AesCtrHmacStreamingParamsStruct>()
        .AddUint32Field(
            1, &AesCtrHmacStreamingParamsStruct::ciphertext_segment_size)
        .AddUint32Field(2, &AesCtrHmacStreamingParamsStruct::derived_key_size)
        .AddEnumField(3, &AesCtrHmacStreamingParamsStruct::hkdf_hash_type,
                      &HashTypeEnumIsValid)
        .AddMessageField(4, &AesCtrHmacStreamingParamsStruct::hmac_params,
                         HmacParamsStruct::CreateParser())
        .BuildOrDie();
  }
};

struct AesCtrHmacStreamingKeyFormatStruct {
  uint32_t version;
  AesCtrHmacStreamingParamsStruct params;
  uint32_t key_size;

  static ProtoParser<AesCtrHmacStreamingKeyFormatStruct> CreateParser() {
    return ProtoParserBuilder<AesCtrHmacStreamingKeyFormatStruct>()
        .AddUint32Field(3, &AesCtrHmacStreamingKeyFormatStruct::version)
        .AddMessageField(1, &AesCtrHmacStreamingKeyFormatStruct::params,
                         AesCtrHmacStreamingParamsStruct::CreateParser())
        .AddUint32Field(2, &AesCtrHmacStreamingKeyFormatStruct::key_size)
        .BuildOrDie();
  }

  static const ProtoParser<AesCtrHmacStreamingKeyFormatStruct>& Parser() {
    static absl::NoDestructor<ProtoParser<AesCtrHmacStreamingKeyFormatStruct>>
        parser{AesCtrHmacStreamingKeyFormatStruct::CreateParser()};
    return *parser;
  }
};

struct AesCtrHmacStreamingKeyStruct {
  uint32_t version;
  AesCtrHmacStreamingParamsStruct params;
  SecretData key_value;

  static ProtoParser<AesCtrHmacStreamingKeyStruct> CreateParser() {
    return ProtoParserBuilder<AesCtrHmacStreamingKeyStruct>()
        .AddUint32Field(1, &AesCtrHmacStreamingKeyStruct::version)
        .AddMessageField(2, &AesCtrHmacStreamingKeyStruct::params,
                         AesCtrHmacStreamingParamsStruct::CreateParser())
        .AddBytesSecretDataField(3, &AesCtrHmacStreamingKeyStruct::key_value)
        .BuildOrDie();
  }

  static const ProtoParser<AesCtrHmacStreamingKeyStruct>& Parser() {
    static absl::NoDestructor<ProtoParser<AesCtrHmacStreamingKeyStruct>> parser{
        AesCtrHmacStreamingKeyStruct::CreateParser()};
    return *parser;
  }
};

using AesCtrHmacStreamingProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization,
                         AesCtrHmacStreamingParameters>;
using AesCtrHmacStreamingProtoParametersSerializerImpl =
    ParametersSerializerImpl<AesCtrHmacStreamingParameters,
                             ProtoParametersSerialization>;
using AesCtrHmacStreamingProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, AesCtrHmacStreamingKey>;
using AesCtrHmacStreamingProtoKeySerializerImpl =
    KeySerializerImpl<AesCtrHmacStreamingKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";

absl::StatusOr<AesCtrHmacStreamingParameters::HashType> FromProtoHashType(
    HashTypeEnum hash_type) {
  switch (hash_type) {
    case HashTypeEnum::kSha1:
      return AesCtrHmacStreamingParameters::HashType::kSha1;
    case HashTypeEnum::kSha256:
      return AesCtrHmacStreamingParameters::HashType::kSha256;
    case HashTypeEnum::kSha512:
      return AesCtrHmacStreamingParameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError("Unsupported proto hash type");
  }
}

absl::StatusOr<HashTypeEnum> ToProtoHashType(
    AesCtrHmacStreamingParameters::HashType hash_type) {
  switch (hash_type) {
    case AesCtrHmacStreamingParameters::HashType::kSha1:
      return HashTypeEnum::kSha1;
    case AesCtrHmacStreamingParameters::HashType::kSha256:
      return HashTypeEnum::kSha256;
    case AesCtrHmacStreamingParameters::HashType::kSha512:
      return HashTypeEnum::kSha512;
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("Unsupported hash type: ", hash_type));
  }
}

absl::StatusOr<AesCtrHmacStreamingParameters> ToParameters(
    const AesCtrHmacStreamingParamsStruct& params_struct, int key_size) {
  absl::StatusOr<AesCtrHmacStreamingParameters::HashType> hkdf_hash_type =
      FromProtoHashType(params_struct.hkdf_hash_type);
  if (!hkdf_hash_type.ok()) {
    return hkdf_hash_type.status();
  }
  absl::StatusOr<AesCtrHmacStreamingParameters::HashType> hmac_hash_type =
      FromProtoHashType(params_struct.hmac_params.hash);
  if (!hmac_hash_type.ok()) {
    return hmac_hash_type.status();
  }

  return AesCtrHmacStreamingParameters::Builder()
      .SetKeySizeInBytes(key_size)
      .SetDerivedKeySizeInBytes(params_struct.derived_key_size)
      .SetHkdfHashType(*hkdf_hash_type)
      .SetHmacHashType(*hmac_hash_type)
      .SetHmacTagSizeInBytes(params_struct.hmac_params.tag_size)
      .SetCiphertextSegmentSizeInBytes(params_struct.ciphertext_segment_size)
      .Build();
}

absl::StatusOr<AesCtrHmacStreamingParamsStruct> FromParameters(
    const AesCtrHmacStreamingParameters& parameters) {
  absl::StatusOr<HashTypeEnum> hkdf_hash_type =
      ToProtoHashType(parameters.HkdfHashType());
  if (!hkdf_hash_type.ok()) {
    return hkdf_hash_type.status();
  }
  absl::StatusOr<HashTypeEnum> hmac_hash_type =
      ToProtoHashType(parameters.HmacHashType());
  if (!hmac_hash_type.ok()) {
    return hmac_hash_type.status();
  }

  AesCtrHmacStreamingParamsStruct params;
  params.derived_key_size = parameters.DerivedKeySizeInBytes();
  params.hkdf_hash_type = *hkdf_hash_type;
  params.hmac_params.hash = *hmac_hash_type;
  params.hmac_params.tag_size = parameters.HmacTagSizeInBytes();
  params.ciphertext_segment_size = parameters.CiphertextSegmentSizeInBytes();
  return params;
}

absl::StatusOr<AesCtrHmacStreamingParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateStruct& key_template = serialization.GetKeyTemplateStruct();
  if (key_template.type_url != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesCtrHmacStreamingParameters.");
  }
  absl::StatusOr<AesCtrHmacStreamingKeyFormatStruct> key_format_struct =
      AesCtrHmacStreamingKeyFormatStruct::Parser().Parse(key_template.value);
  if (!key_format_struct.ok()) {
    return key_format_struct.status();
  }
  if (key_format_struct->version != 0) {
    return absl::InvalidArgumentError(
        "Parsing AesCtrHmacStreamingKeyFormat failed: only "
        "version 0 is accepted.");
  }
  return ToParameters(key_format_struct->params, key_format_struct->key_size);
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const AesCtrHmacStreamingParameters& parameters) {
  absl::StatusOr<AesCtrHmacStreamingParamsStruct> params_struct =
      FromParameters(parameters);
  if (!params_struct.ok()) {
    return params_struct.status();
  }
  AesCtrHmacStreamingKeyFormatStruct format;
  format.version = 0;
  format.key_size = parameters.KeySizeInBytes();
  format.params = *params_struct;

  absl::StatusOr<std::string> serialized_format =
      AesCtrHmacStreamingKeyFormatStruct::Parser().SerializeIntoString(format);
  if (!serialized_format.ok()) {
    return serialized_format.status();
  }

  return ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixTypeEnum::kRaw, *serialized_format);
}

absl::StatusOr<AesCtrHmacStreamingKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesCtrHmacStreamingKey.");
  }

  absl::StatusOr<AesCtrHmacStreamingKeyStruct> parsed_key_struct =
      AesCtrHmacStreamingKeyStruct::Parser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!parsed_key_struct.ok()) {
    return parsed_key_struct.status();
  }

  if (parsed_key_struct->version != 0) {
    return absl::InvalidArgumentError(
        "Parsing AesCtrHmacStreamingKey failed: only version 0 is accepted.");
  }

  absl::StatusOr<AesCtrHmacStreamingParameters> parameters = ToParameters(
      parsed_key_struct->params, parsed_key_struct->key_value.size());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return AesCtrHmacStreamingKey::Create(
      *parameters, RestrictedData(parsed_key_struct->key_value, *token),
      GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const AesCtrHmacStreamingKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  absl::StatusOr<RestrictedData> initial_key_material =
      key.GetInitialKeyMaterial(GetPartialKeyAccess());
  if (!initial_key_material.ok()) {
    return initial_key_material.status();
  }
  absl::StatusOr<AesCtrHmacStreamingParamsStruct> params_struct =
      FromParameters(key.GetParameters());
  if (!params_struct.ok()) {
    return params_struct.status();
  }

  AesCtrHmacStreamingKeyStruct key_struct;
  key_struct.version = 0;
  key_struct.params = *params_struct;
  key_struct.key_value =
      util::SecretDataFromStringView(initial_key_material->GetSecret(*token));

  absl::StatusOr<SecretData> serialized_key =
      AesCtrHmacStreamingKeyStruct::Parser().SerializeIntoSecretData(
          key_struct);
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  return ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(*std::move(serialized_key), *token),
      KeyMaterialTypeEnum::kSymmetric, OutputPrefixTypeEnum::kRaw,
      key.GetIdRequirement());
}

AesCtrHmacStreamingProtoParametersParserImpl*
AesCtrHmacStreamingProtoParametersParser() {
  static auto* parser = new AesCtrHmacStreamingProtoParametersParserImpl(
      kTypeUrl, ParseParameters);
  return parser;
}

AesCtrHmacStreamingProtoParametersSerializerImpl*
AesCtrHmacStreamingProtoParametersSerializer() {
  static auto* serializer =
      new AesCtrHmacStreamingProtoParametersSerializerImpl(kTypeUrl,
                                                           SerializeParameters);
  return serializer;
}

AesCtrHmacStreamingProtoKeyParserImpl* AesCtrHmacStreamingProtoKeyParser() {
  static auto* parser =
      new AesCtrHmacStreamingProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesCtrHmacStreamingProtoKeySerializerImpl*
AesCtrHmacStreamingProtoKeySerializer() {
  static auto* serializer =
      new AesCtrHmacStreamingProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterAesCtrHmacStreamingProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status = registry.RegisterParametersParser(
      AesCtrHmacStreamingProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      AesCtrHmacStreamingProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(AesCtrHmacStreamingProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(
      AesCtrHmacStreamingProtoKeySerializer());
}

absl::Status RegisterAesCtrHmacStreamingProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status = builder.RegisterParametersParser(
      AesCtrHmacStreamingProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterParametersSerializer(
      AesCtrHmacStreamingProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(AesCtrHmacStreamingProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(AesCtrHmacStreamingProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
