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

#include "tink/prf/internal/hmac_prf_proto_serialization_impl.h"

#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/no_destructor.h"
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
#include "tink/partial_key_access.h"
#include "tink/prf/hmac_prf_key.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/hmac_prf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;
using ::crypto::tink::util::SecretData;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::OutputPrefixType;

bool HashTypeValid(int c) { return google::crypto::tink::HashType_IsValid(c); }

struct HmacPrfParamsStruct {
  HashType hash;

  static ProtoParser<HmacPrfParamsStruct> CreateParser() {
    return ProtoParserBuilder<HmacPrfParamsStruct>()
        .AddEnumField(1, &HmacPrfParamsStruct::hash, HashTypeValid)
        .BuildOrDie();
  }

  static const ProtoParser<HmacPrfParamsStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<HmacPrfParamsStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

struct HmacPrfKeyStruct {
  uint32_t version;
  HmacPrfParamsStruct params;
  SecretData key_value;

  static ProtoParser<HmacPrfKeyStruct> CreateParser() {
    return ProtoParserBuilder<HmacPrfKeyStruct>()
        .AddUint32Field(1, &HmacPrfKeyStruct::version)
        .AddMessageField(2, &HmacPrfKeyStruct::params,
                         HmacPrfParamsStruct::CreateParser())
        .AddBytesSecretDataField(3, &HmacPrfKeyStruct::key_value)
        .BuildOrDie();
  }

  static const ProtoParser<HmacPrfKeyStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<HmacPrfKeyStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

struct HmacPrfKeyFormatStruct {
  HmacPrfParamsStruct params;
  uint32_t key_size;
  uint32_t version;

  static ProtoParser<HmacPrfKeyFormatStruct> CreateParser() {
    return ProtoParserBuilder<HmacPrfKeyFormatStruct>()
        .AddMessageField(1, &HmacPrfKeyFormatStruct::params,
                         HmacPrfParamsStruct::CreateParser())
        .AddUint32Field(2, &HmacPrfKeyFormatStruct::key_size)
        .AddUint32Field(3, &HmacPrfKeyFormatStruct::version)
        .BuildOrDie();
  }

  static const ProtoParser<HmacPrfKeyFormatStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<HmacPrfKeyFormatStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

using HmacPrfProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, HmacPrfParameters>;
using HmacPrfProtoParametersSerializerImpl =
    ParametersSerializerImpl<HmacPrfParameters, ProtoParametersSerialization>;
using HmacPrfProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, HmacPrfKey>;
using HmacPrfProtoKeySerializerImpl =
    KeySerializerImpl<HmacPrfKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.HmacPrfKey";

util::StatusOr<HmacPrfParameters::HashType> ToHashType(HashType hash_type) {
  switch (hash_type) {
    case HashType::SHA1:
      return HmacPrfParameters::HashType::kSha1;
    case HashType::SHA224:
      return HmacPrfParameters::HashType::kSha224;
    case HashType::SHA256:
      return HmacPrfParameters::HashType::kSha256;
    case HashType::SHA384:
      return HmacPrfParameters::HashType::kSha384;
    case HashType::SHA512:
      return HmacPrfParameters::HashType::kSha512;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HashType");
  }
}

util::StatusOr<HashType> ToProtoHashType(
    HmacPrfParameters::HashType hash_type) {
  switch (hash_type) {
    case HmacPrfParameters::HashType::kSha1:
      return HashType::SHA1;
    case HmacPrfParameters::HashType::kSha224:
      return HashType::SHA224;
    case HmacPrfParameters::HashType::kSha256:
      return HashType::SHA256;
    case HmacPrfParameters::HashType::kSha384:
      return HashType::SHA384;
    case HmacPrfParameters::HashType::kSha512:
      return HashType::SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HmacPrfParameters::HashType");
  }
}

util::StatusOr<HmacPrfParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing HmacPrfParameters.");
  }
  if (serialization.GetKeyTemplate().output_prefix_type() !=
      OutputPrefixType::RAW) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Output prefix type must be RAW for HmacPrfParameters.");
  }

  util::StatusOr<HmacPrfKeyFormatStruct> proto_key_format =
      HmacPrfKeyFormatStruct::GetParser().Parse(
          serialization.GetKeyTemplate().value());
  if (!proto_key_format.ok()) {
    return proto_key_format.status();
  }
  if (proto_key_format->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<HmacPrfParameters::HashType> hash_type =
      ToHashType(proto_key_format->params.hash);
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  return HmacPrfParameters::Create(proto_key_format->key_size, *hash_type);
}

util::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const HmacPrfParameters& parameters) {
  util::StatusOr<HashType> proto_hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!proto_hash_type.ok()) {
    return proto_hash_type.status();
  }

  HmacPrfKeyFormatStruct proto_key_format;
  proto_key_format.params.hash = *proto_hash_type;
  proto_key_format.key_size = parameters.KeySizeInBytes();
  proto_key_format.version = 0;

  util::StatusOr<std::string> serialized_key_format =
      HmacPrfKeyFormatStruct::GetParser().SerializeIntoString(proto_key_format);
  if (!serialized_key_format.ok()) {
    return serialized_key_format.status();
  }

  return ProtoParametersSerialization::Create(kTypeUrl, OutputPrefixType::RAW,
                                              *serialized_key_format);
}

util::StatusOr<HmacPrfKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing HmacPrfKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required.");
  }
  if (serialization.GetOutputPrefixType() != OutputPrefixType::RAW) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Output prefix type must be RAW for HmacPrfKey.");
  }

  util::StatusOr<HmacPrfKeyStruct> proto_key =
      HmacPrfKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!proto_key.ok()) {
    return proto_key.status();
  }
  if (proto_key->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<HmacPrfParameters::HashType> hash_type =
      ToHashType(proto_key->params.hash);
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  util::StatusOr<HmacPrfParameters> parameters =
      HmacPrfParameters::Create(proto_key->key_value.size(), *hash_type);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return HmacPrfKey::Create(*parameters,
                            RestrictedData(proto_key->key_value, *token),
                            GetPartialKeyAccess());
}

util::StatusOr<ProtoKeySerialization> SerializeKey(
    const HmacPrfKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required.");
  }
  util::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  util::StatusOr<HashType> proto_hash_type =
      ToProtoHashType(key.GetParameters().GetHashType());
  if (!proto_hash_type.ok()) {
    return proto_hash_type.status();
  }

  HmacPrfKeyStruct proto_key;
  proto_key.version = 0;
  proto_key.params.hash = *proto_hash_type;
  proto_key.key_value = restricted_input->Get(*token);

  util::StatusOr<SecretData> serialized_key =
      HmacPrfKeyStruct::GetParser().SerializeIntoSecretData(proto_key);
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*std::move(serialized_key), *token);

  return ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, google::crypto::tink::KeyData::SYMMETRIC,
      OutputPrefixType::RAW, key.GetIdRequirement());
}

HmacPrfProtoParametersParserImpl& HmacPrfProtoParametersParser() {
  static auto* parser =
      new HmacPrfProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return *parser;
}

HmacPrfProtoParametersSerializerImpl& HmacPrfProtoParametersSerializer() {
  static auto* serializer =
      new HmacPrfProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return *serializer;
}

HmacPrfProtoKeyParserImpl& HmacPrfProtoKeyParser() {
  static auto* parser = new HmacPrfProtoKeyParserImpl(kTypeUrl, ParseKey);
  return *parser;
}

HmacPrfProtoKeySerializerImpl& HmacPrfProtoKeySerializer() {
  static auto* serializer = new HmacPrfProtoKeySerializerImpl(SerializeKey);
  return *serializer;
}

}  // namespace

util::Status RegisterHmacPrfProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  util::Status status =
      registry.RegisterParametersParser(&HmacPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      &HmacPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(&HmacPrfProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(&HmacPrfProtoKeySerializer());
}

util::Status RegisterHmacPrfProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  util::Status status =
      builder.RegisterParametersParser(&HmacPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      builder.RegisterParametersSerializer(&HmacPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(&HmacPrfProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(&HmacPrfProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
