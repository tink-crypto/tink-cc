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

#include "tink/prf/internal/aes_cmac_prf_proto_serialization_impl.h"

#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
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
#include "tink/prf/aes_cmac_prf_key.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
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

struct AesCmacPrfKeyFormatStruct {
  uint32_t key_size;
  uint32_t version;

  static ProtoParser<AesCmacPrfKeyFormatStruct> CreateParser() {
    return ProtoParserBuilder<AesCmacPrfKeyFormatStruct>()
        .AddUint32Field(1, &AesCmacPrfKeyFormatStruct::key_size)
        .AddUint32Field(2, &AesCmacPrfKeyFormatStruct::version)
        .BuildOrDie();
  }

  static const ProtoParser<AesCmacPrfKeyFormatStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<AesCmacPrfKeyFormatStruct>>
        parser{CreateParser()};
    return *parser;
  }
};

struct AesCmacPrfKeyStruct {
  uint32_t version;
  SecretData key_value;

  static ProtoParser<AesCmacPrfKeyStruct> CreateParser() {
    return ProtoParserBuilder<AesCmacPrfKeyStruct>()
        .AddUint32Field(1, &AesCmacPrfKeyStruct::version)
        .AddBytesSecretDataField(2, &AesCmacPrfKeyStruct::key_value)
        .BuildOrDie();
  }

  static const ProtoParser<AesCmacPrfKeyStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<AesCmacPrfKeyStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

using AesCmacPrfProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   AesCmacPrfParameters>;
using AesCmacPrfProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<AesCmacPrfParameters,
                                       internal::ProtoParametersSerialization>;
using AesCmacPrfProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, AesCmacPrfKey>;
using AesCmacPrfProtoKeySerializerImpl =
    internal::KeySerializerImpl<AesCmacPrfKey, internal::ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCmacPrfKey";

absl::StatusOr<AesCmacPrfParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  const KeyTemplateStruct& key_template = serialization.GetKeyTemplateStruct();
  if (key_template.type_url != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesCmacPrfParameters.");
  }
  if (key_template.output_prefix_type != OutputPrefixTypeEnum::kRaw) {
    return absl::InvalidArgumentError(
        "Output prefix type must be RAW for AesCmacPrfParameters.");
  }

  absl::StatusOr<AesCmacPrfKeyFormatStruct> proto_key_format =
      AesCmacPrfKeyFormatStruct::GetParser().Parse(key_template.value);
  if (!proto_key_format.ok()) {
    return proto_key_format.status();
  }
  if (proto_key_format->version != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  return AesCmacPrfParameters::Create(proto_key_format->key_size);
}

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const AesCmacPrfParameters& parameters) {
  AesCmacPrfKeyFormatStruct proto_key_format;
  proto_key_format.key_size = parameters.KeySizeInBytes();
  proto_key_format.version = 0;

  absl::StatusOr<std::string> serialized_key_format =
      AesCmacPrfKeyFormatStruct::GetParser().SerializeIntoString(
          proto_key_format);
  if (!serialized_key_format.ok()) {
    return serialized_key_format.status();
  }

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixTypeEnum::kRaw, *serialized_key_format);
}

absl::StatusOr<AesCmacPrfKey> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesCmacPrfKey.");
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  if (serialization.GetOutputPrefixTypeEnum() != OutputPrefixTypeEnum::kRaw) {
    return absl::InvalidArgumentError(
        "Output prefix type must be RAW for AesCmacPrfKey.");
  }

  absl::StatusOr<AesCmacPrfKeyStruct> proto_key =
      AesCmacPrfKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!proto_key.ok()) {
    return proto_key.status();
  }
  if (proto_key->version != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  return AesCmacPrfKey::Create(RestrictedData(proto_key->key_value, *token),
                               GetPartialKeyAccess());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const AesCmacPrfKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  AesCmacPrfKeyStruct proto_key;
  proto_key.version = 0;
  proto_key.key_value = restricted_input->Get(*token);

  absl::StatusOr<SecretData> serialized_key =
      AesCmacPrfKeyStruct::GetParser().SerializeIntoSecretData(proto_key);
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*std::move(serialized_key), *token);

  return internal::ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, KeyMaterialTypeEnum::kSymmetric,
      OutputPrefixTypeEnum::kRaw, key.GetIdRequirement());
}

AesCmacPrfProtoParametersParserImpl* AesCmacPrfProtoParametersParser() {
  static auto* parser =
      new AesCmacPrfProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

AesCmacPrfProtoParametersSerializerImpl* AesCmacPrfProtoParametersSerializer() {
  static auto* serializer = new AesCmacPrfProtoParametersSerializerImpl(
      kTypeUrl, SerializeParameters);
  return serializer;
}

AesCmacPrfProtoKeyParserImpl* AesCmacPrfProtoKeyParser() {
  static auto* parser = new AesCmacPrfProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesCmacPrfProtoKeySerializerImpl* AesCmacPrfProtoKeySerializer() {
  static auto* serializer = new AesCmacPrfProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterAesCmacPrfProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(AesCmacPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      AesCmacPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(AesCmacPrfProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(AesCmacPrfProtoKeySerializer());
}

absl::Status RegisterAesCmacPrfProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(AesCmacPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterParametersSerializer(
      AesCmacPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(AesCmacPrfProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(AesCmacPrfProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
