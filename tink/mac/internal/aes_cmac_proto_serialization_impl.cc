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

#include "tink/mac/internal/aes_cmac_proto_serialization_impl.h"

#include <cstdint>
#include <string>
#include <utility>

#include "absl/status/status.h"
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
#include "tink/mac/aes_cmac_key.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretDataFromStringView;
using ::google::crypto::tink::OutputPrefixType;

struct AesCmacParamStruct {
  uint32_t tag_size;
};

struct AesCmacKeyStruct {
  uint32_t version;
  SecretData key_value;
  AesCmacParamStruct params;
};

struct AesCmacKeyFormatStruct {
  uint32_t key_size;
  AesCmacParamStruct params;
};

ProtoParser<AesCmacParamStruct> CreateParamParser() {
  return ProtoParserBuilder<AesCmacParamStruct>()
      .AddUint32Field(1, &AesCmacParamStruct::tag_size)
      .BuildOrDie();
}

ProtoParser<AesCmacKeyStruct> CreateKeyParser() {
  return ProtoParserBuilder<AesCmacKeyStruct>()
      .AddUint32Field(1, &AesCmacKeyStruct::version)
      .AddBytesSecretDataField(2, &AesCmacKeyStruct::key_value)
      .AddMessageField(3, &AesCmacKeyStruct::params, CreateParamParser())
      .BuildOrDie();
}

const ProtoParser<AesCmacKeyStruct>& GetKeyParser() {
  static ProtoParser<AesCmacKeyStruct>* parser =
      new ProtoParser<AesCmacKeyStruct>(CreateKeyParser());
  return *parser;
}

ProtoParser<AesCmacKeyFormatStruct> CreateFormatParser() {
  return ProtoParserBuilder<AesCmacKeyFormatStruct>()
      .AddUint32Field(1, &AesCmacKeyFormatStruct::key_size)
      .AddMessageField(2, &AesCmacKeyFormatStruct::params, CreateParamParser())
      .BuildOrDie();
}

const ProtoParser<AesCmacKeyFormatStruct>& GetFormatParser() {
  static ProtoParser<AesCmacKeyFormatStruct>* parser =
      new ProtoParser<AesCmacKeyFormatStruct>(CreateFormatParser());
  return *parser;
}

using AesCmacProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, AesCmacParameters>;
using AesCmacProtoParametersSerializerImpl =
    ParametersSerializerImpl<AesCmacParameters, ProtoParametersSerialization>;
using AesCmacProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, AesCmacKey>;
using AesCmacProtoKeySerializerImpl =
    KeySerializerImpl<AesCmacKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCmacKey";

util::StatusOr<AesCmacParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::CRUNCHY:
      return AesCmacParameters::Variant::kCrunchy;
    case OutputPrefixType::LEGACY:
      return AesCmacParameters::Variant::kLegacy;
    case OutputPrefixType::RAW:
      return AesCmacParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return AesCmacParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine AesCmacParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    AesCmacParameters::Variant variant) {
  switch (variant) {
    case AesCmacParameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case AesCmacParameters::Variant::kLegacy:
      return OutputPrefixType::LEGACY;
    case AesCmacParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case AesCmacParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<AesCmacParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesCmacParameters.");
  }

  util::StatusOr<AesCmacKeyFormatStruct> proto_key_format =
      GetFormatParser().Parse(serialization.GetKeyTemplate().value());
  if (!proto_key_format.ok()) {
    return proto_key_format.status();
  }

  util::StatusOr<AesCmacParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) return variant.status();

  return AesCmacParameters::Create(proto_key_format->key_size,
                                   proto_key_format->params.tag_size, *variant);
}

util::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const AesCmacParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  AesCmacKeyFormatStruct proto_key_format;
  proto_key_format.params.tag_size = parameters.CryptographicTagSizeInBytes();
  proto_key_format.key_size = parameters.KeySizeInBytes();

  util::StatusOr<std::string> serialized =
      GetFormatParser().SerializeIntoString(proto_key_format);
  if (!serialized.ok()) {
    return serialized.status();
  }
  return ProtoParametersSerialization::Create(kTypeUrl, *output_prefix_type,
                                              *serialized);
}

util::StatusOr<AesCmacKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesCmacKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }
  util::StatusOr<AesCmacKeyStruct> proto_key = GetKeyParser().Parse(
      SecretDataAsStringView(serialization.SerializedKeyProto().Get(*token)));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesCmacKey proto");
  }
  if (proto_key->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<AesCmacParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) return variant.status();

  util::StatusOr<AesCmacParameters> parameters = AesCmacParameters::Create(
      proto_key->key_value.size(), proto_key->params.tag_size, *variant);
  if (!parameters.ok()) return parameters.status();

  util::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *parameters, RestrictedData(proto_key->key_value, *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
  if (!key.ok()) return key.status();

  return *key;
}

util::StatusOr<ProtoKeySerialization> SerializeKey(
    const AesCmacKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) return restricted_input.status();
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }

  AesCmacKeyStruct proto_key;
  proto_key.params.tag_size = key.GetParameters().CryptographicTagSizeInBytes();
  proto_key.version = 0;
  proto_key.key_value =
      SecretDataFromStringView(restricted_input->GetSecret(*token));

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  util::StatusOr<SecretData> serialized_key =
      GetKeyParser().SerializeIntoSecretData(proto_key);
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*std::move(serialized_key), *token);
  return ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, google::crypto::tink::KeyData::SYMMETRIC,
      *output_prefix_type, key.GetIdRequirement());
}

AesCmacProtoParametersParserImpl* AesCmacProtoParametersParser() {
  static auto* parser =
      new AesCmacProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

AesCmacProtoParametersSerializerImpl* AesCmacProtoParametersSerializer() {
  static auto* serializer =
      new AesCmacProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

AesCmacProtoKeyParserImpl* AesCmacProtoKeyParser() {
  static auto* parser = new AesCmacProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesCmacProtoKeySerializerImpl* AesCmacProtoKeySerializer() {
  static auto* serializer = new AesCmacProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

util::Status RegisterAesCmacProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  util::Status status =
      registry.RegisterParametersParser(AesCmacProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      registry.RegisterParametersSerializer(AesCmacProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(AesCmacProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(AesCmacProtoKeySerializer());
}

util::Status RegisterAesCmacProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  util::Status status =
      builder.RegisterParametersParser(AesCmacProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      builder.RegisterParametersSerializer(AesCmacProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(AesCmacProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(AesCmacProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
