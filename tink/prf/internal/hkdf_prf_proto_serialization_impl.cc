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

#include "tink/prf/internal/hkdf_prf_proto_serialization_impl.h"

#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/no_destructor.h"
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
#include "tink/internal/proto_parser.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
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

struct HkdfPrfParamsStruct {
  HashTypeEnum hash;
  std::string salt;

  static ProtoParser<HkdfPrfParamsStruct> CreateParser() {
    return ProtoParserBuilder<HkdfPrfParamsStruct>()
        .AddEnumField(1, &HkdfPrfParamsStruct::hash, &HashTypeEnumIsValid)
        .AddBytesStringField(2, &HkdfPrfParamsStruct::salt)
        .BuildOrDie();
  }

  static const ProtoParser<HkdfPrfParamsStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<HkdfPrfParamsStruct>> kParser(
        CreateParser());
    return *kParser;
  }
};

struct HkdfPrfKeyStruct {
  uint32_t version;
  HkdfPrfParamsStruct params;
  util::SecretData key_value;

  static ProtoParser<HkdfPrfKeyStruct> CreateParser() {
    return ProtoParserBuilder<HkdfPrfKeyStruct>()
        .AddUint32Field(1, &HkdfPrfKeyStruct::version)
        .AddMessageField(2, &HkdfPrfKeyStruct::params,
                         HkdfPrfParamsStruct::CreateParser())
        .AddBytesSecretDataField(3, &HkdfPrfKeyStruct::key_value)
        .BuildOrDie();
  }

  static const ProtoParser<HkdfPrfKeyStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<HkdfPrfKeyStruct>> kParser(
        CreateParser());
    return *kParser;
  }
};

struct HkdfPrfKeyFormatStruct {
  HkdfPrfParamsStruct params;
  uint32_t key_size;
  uint32_t version;

  static ProtoParser<HkdfPrfKeyFormatStruct> CreateParser() {
    return ProtoParserBuilder<HkdfPrfKeyFormatStruct>()
        .AddMessageField(1, &HkdfPrfKeyFormatStruct::params,
                         HkdfPrfParamsStruct::CreateParser())
        .AddUint32Field(2, &HkdfPrfKeyFormatStruct::key_size)
        .AddUint32Field(3, &HkdfPrfKeyFormatStruct::version)
        .BuildOrDie();
  }

  static const ProtoParser<HkdfPrfKeyFormatStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<HkdfPrfKeyFormatStruct>>
        kParser(CreateParser());
    return *kParser;
  }
};

using HkdfPrfProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, HkdfPrfParameters>;
using HkdfPrfProtoParametersSerializerImpl =
    ParametersSerializerImpl<HkdfPrfParameters, ProtoParametersSerialization>;
using HkdfPrfProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, HkdfPrfKey>;
using HkdfPrfProtoKeySerializerImpl =
    KeySerializerImpl<HkdfPrfKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.HkdfPrfKey";

absl::StatusOr<HkdfPrfParameters::HashType> ToHashType(HashTypeEnum hash_type) {
  switch (hash_type) {
    case HashTypeEnum::kSha1:
      return HkdfPrfParameters::HashType::kSha1;
    case HashTypeEnum::kSha224:
      return HkdfPrfParameters::HashType::kSha224;
    case HashTypeEnum::kSha256:
      return HkdfPrfParameters::HashType::kSha256;
    case HashTypeEnum::kSha384:
      return HkdfPrfParameters::HashType::kSha384;
    case HashTypeEnum::kSha512:
      return HkdfPrfParameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError("Could not determine HashType");
  }
}

absl::StatusOr<HashTypeEnum> ToProtoHashType(
    HkdfPrfParameters::HashType hash_type) {
  switch (hash_type) {
    case HkdfPrfParameters::HashType::kSha1:
      return HashTypeEnum::kSha1;
    case HkdfPrfParameters::HashType::kSha224:
      return HashTypeEnum::kSha224;
    case HkdfPrfParameters::HashType::kSha256:
      return HashTypeEnum::kSha256;
    case HkdfPrfParameters::HashType::kSha384:
      return HashTypeEnum::kSha384;
    case HkdfPrfParameters::HashType::kSha512:
      return HashTypeEnum::kSha512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine HkdfPrfParameters::HashType");
  }
}

absl::StatusOr<HkdfPrfParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplateStruct().type_url != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing HkdfPrfParameters.");
  }
  if (serialization.GetKeyTemplateStruct().output_prefix_type !=
      OutputPrefixTypeEnum::kRaw) {
    return absl::InvalidArgumentError(
        "Output prefix type must be RAW for HkdfPrfParameters.");
  }

  absl::StatusOr<HkdfPrfKeyFormatStruct> proto_key_format =
      HkdfPrfKeyFormatStruct::GetParser().Parse(
          serialization.GetKeyTemplateStruct().value);
  if (!proto_key_format.ok()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse HkdfPrfKeyFormat proto");
  }
  if (proto_key_format->version != 0) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  absl::StatusOr<HkdfPrfParameters::HashType> hash_type =
      ToHashType(proto_key_format->params.hash);
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  if (!proto_key_format->params.salt.empty()) {
    return HkdfPrfParameters::Create(proto_key_format->key_size, *hash_type,
                                     proto_key_format->params.salt);
  }

  return HkdfPrfParameters::Create(proto_key_format->key_size, *hash_type,
                                   absl::nullopt);
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const HkdfPrfParameters& parameters) {
  absl::StatusOr<HashTypeEnum> proto_hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!proto_hash_type.ok()) {
    return proto_hash_type.status();
  }

  HkdfPrfKeyFormatStruct proto_key_format;
  proto_key_format.version = 0;
  proto_key_format.key_size = parameters.KeySizeInBytes();
  proto_key_format.params.hash = *proto_hash_type;
  if (parameters.GetSalt().has_value()) {
    proto_key_format.params.salt = *parameters.GetSalt();
  }

  absl::StatusOr<std::string> serialized_key_format =
      HkdfPrfKeyFormatStruct::GetParser().SerializeIntoString(proto_key_format);
  if (!serialized_key_format.ok()) {
    return serialized_key_format.status();
  }

  return ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixTypeEnum::kRaw, *serialized_key_format);
}

absl::StatusOr<HkdfPrfKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing HkdfPrfKey.");
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  if (serialization.GetOutputPrefixTypeEnum() != OutputPrefixTypeEnum::kRaw) {
    return absl::InvalidArgumentError(
        "Output prefix type must be RAW for HkdfPrfKey.");
  }

  absl::StatusOr<HkdfPrfKeyStruct> proto_key =
      HkdfPrfKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!proto_key.ok()) {
    return proto_key.status();
  }
  if (proto_key->version != 0) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  absl::StatusOr<HkdfPrfParameters::HashType> hash_type =
      ToHashType(proto_key->params.hash);
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  absl::optional<std::string> salt = absl::nullopt;
  if (!proto_key->params.salt.empty()) {
    salt = proto_key->params.salt;
  }

  absl::StatusOr<HkdfPrfParameters> parameters =
      HkdfPrfParameters::Create(proto_key->key_value.size(), *hash_type, salt);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return HkdfPrfKey::Create(*parameters,
                            RestrictedData(proto_key->key_value, *token),
                            GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const HkdfPrfKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  absl::StatusOr<HashTypeEnum> proto_hash_type =
      ToProtoHashType(key.GetParameters().GetHashType());
  if (!proto_hash_type.ok()) {
    return proto_hash_type.status();
  }

  HkdfPrfKeyStruct proto_key;
  proto_key.version = 0;
  proto_key.params.hash = *proto_hash_type;
  if (key.GetParameters().GetSalt().has_value()) {
    proto_key.params.salt = *key.GetParameters().GetSalt();
  }
  proto_key.key_value = restricted_input->Get(*token);

  absl::StatusOr<SecretData> serialized_key =
      HkdfPrfKeyStruct::GetParser().SerializeIntoSecretData(proto_key);
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*std::move(serialized_key), *token);

  return ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, KeyMaterialTypeEnum::kSymmetric,
      OutputPrefixTypeEnum::kRaw, key.GetIdRequirement());
}

HkdfPrfProtoParametersParserImpl& HkdfPrfProtoParametersParser() {
  static auto* parser =
      new HkdfPrfProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return *parser;
}

HkdfPrfProtoParametersSerializerImpl& HkdfPrfProtoParametersSerializer() {
  static auto* serializer =
      new HkdfPrfProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return *serializer;
}

HkdfPrfProtoKeyParserImpl& HkdfPrfProtoKeyParser() {
  static auto* parser = new HkdfPrfProtoKeyParserImpl(kTypeUrl, ParseKey);
  return *parser;
}

HkdfPrfProtoKeySerializerImpl& HkdfPrfProtoKeySerializer() {
  static auto* serializer = new HkdfPrfProtoKeySerializerImpl(SerializeKey);
  return *serializer;
}

}  // namespace

absl::Status RegisterHkdfPrfProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(&HkdfPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      &HkdfPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(&HkdfPrfProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(&HkdfPrfProtoKeySerializer());
}

absl::Status RegisterHkdfPrfProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(&HkdfPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      builder.RegisterParametersSerializer(&HkdfPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(&HkdfPrfProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(&HkdfPrfProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
