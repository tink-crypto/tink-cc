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

#include "tink/streamingaead/aes_gcm_hkdf_streaming_proto_serialization.h"

#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
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
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_gcm_hkdf_streaming.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::util::SecretData;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;

struct AesGcmHkdfStreamingParamsStruct {
  uint32_t ciphertext_segment_size;
  uint32_t derived_key_size;
  google::crypto::tink::HashType hkdf_hash_type;

  static internal::ProtoParser<AesGcmHkdfStreamingParamsStruct> CreateParser() {
    return internal::ProtoParserBuilder<AesGcmHkdfStreamingParamsStruct>()
        .AddUint32Field(
            1, &AesGcmHkdfStreamingParamsStruct::ciphertext_segment_size)
        .AddUint32Field(2, &AesGcmHkdfStreamingParamsStruct::derived_key_size)
        .AddEnumField(
            3, &AesGcmHkdfStreamingParamsStruct::hkdf_hash_type,
            +[](uint32_t hash_type) {
              return google::crypto::tink::HashType_IsValid(hash_type);
            })
        .BuildOrDie();
  }
};

struct AesGcmHkdfStreamingKeyFormatStruct {
  uint32_t version;
  AesGcmHkdfStreamingParamsStruct params;
  uint32_t key_size;

  static internal::ProtoParser<AesGcmHkdfStreamingKeyFormatStruct>
  CreateParser() {
    return internal::ProtoParserBuilder<AesGcmHkdfStreamingKeyFormatStruct>()
        .AddMessageField(1, &AesGcmHkdfStreamingKeyFormatStruct::params,
                         AesGcmHkdfStreamingParamsStruct::CreateParser())
        .AddUint32Field(2, &AesGcmHkdfStreamingKeyFormatStruct::key_size)
        .AddUint32Field(3, &AesGcmHkdfStreamingKeyFormatStruct::version)
        .BuildOrDie();
  }

  static const internal::ProtoParser<AesGcmHkdfStreamingKeyFormatStruct>&
  Parser() {
    static absl::NoDestructor<
        internal::ProtoParser<AesGcmHkdfStreamingKeyFormatStruct>>
        parser{AesGcmHkdfStreamingKeyFormatStruct::CreateParser()};
    return *parser;
  }
};

struct AesGcmHkdfStreamingKeyStruct {
  uint32_t version;
  AesGcmHkdfStreamingParamsStruct params;
  SecretData key_value;

  static internal::ProtoParser<AesGcmHkdfStreamingKeyStruct> CreateParser() {
    return internal::ProtoParserBuilder<AesGcmHkdfStreamingKeyStruct>()
        .AddUint32Field(1, &AesGcmHkdfStreamingKeyStruct::version)
        .AddMessageField(2, &AesGcmHkdfStreamingKeyStruct::params,
                         AesGcmHkdfStreamingParamsStruct::CreateParser())
        .AddBytesSecretDataField(3, &AesGcmHkdfStreamingKeyStruct::key_value)
        .BuildOrDie();
  }

  static const internal::ProtoParser<AesGcmHkdfStreamingKeyStruct>& Parser() {
    static absl::NoDestructor<
        internal::ProtoParser<AesGcmHkdfStreamingKeyStruct>>
        parser{AesGcmHkdfStreamingKeyStruct::CreateParser()};
    return *parser;
  }
};

using AesGcmHkdfStreamingProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   AesGcmHkdfStreamingParameters>;
using AesGcmHkdfStreamingProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<AesGcmHkdfStreamingParameters,
                                       internal::ProtoParametersSerialization>;
using AesGcmHkdfStreamingProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            AesGcmHkdfStreamingKey>;
using AesGcmHkdfStreamingProtoKeySerializerImpl =
    internal::KeySerializerImpl<AesGcmHkdfStreamingKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

util::StatusOr<AesGcmHkdfStreamingParameters::HashType> FromProtoHashType(
    google::crypto::tink::HashType hash_type) {
  switch (hash_type) {
    case google::crypto::tink::HashType::SHA1:
      return AesGcmHkdfStreamingParameters::HashType::kSha1;
    case google::crypto::tink::HashType::SHA256:
      return AesGcmHkdfStreamingParameters::HashType::kSha256;
    case google::crypto::tink::HashType::SHA512:
      return AesGcmHkdfStreamingParameters::HashType::kSha512;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported proto hash type: ", hash_type));
  }
}

util::StatusOr<google::crypto::tink::HashType> ToProtoHashType(
    AesGcmHkdfStreamingParameters::HashType hash_type) {
  switch (hash_type) {
    case AesGcmHkdfStreamingParameters::HashType::kSha1:
      return google::crypto::tink::HashType::SHA1;
    case AesGcmHkdfStreamingParameters::HashType::kSha256:
      return google::crypto::tink::HashType::SHA256;
    case AesGcmHkdfStreamingParameters::HashType::kSha512:
      return google::crypto::tink::HashType::SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported hash type: ", hash_type));
  }
}

util::StatusOr<AesGcmHkdfStreamingParameters> ToParameters(
    const AesGcmHkdfStreamingParamsStruct& params, int key_size) {
  util::StatusOr<AesGcmHkdfStreamingParameters::HashType> hash_type =
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

util::StatusOr<AesGcmHkdfStreamingParamsStruct> FromParameters(
    const AesGcmHkdfStreamingParameters& parameters) {
  util::StatusOr<google::crypto::tink::HashType> hash_type =
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

util::StatusOr<AesGcmHkdfStreamingParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing AesGcmHkdfStreamingParameters.");
  }

  absl::StatusOr<AesGcmHkdfStreamingKeyFormatStruct> parsed_key_format =
      AesGcmHkdfStreamingKeyFormatStruct::Parser().Parse(
          serialization.GetKeyTemplate().value());
  if (!parsed_key_format.ok()) {
    return parsed_key_format.status();
  }

  if (parsed_key_format->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Parsing AesGcmHkdfStreamingKeyFormat failed: only "
                        "version 0 is accepted.");
  }

  return ToParameters(parsed_key_format->params, parsed_key_format->key_size);
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const AesGcmHkdfStreamingParameters& parameters) {
  util::StatusOr<AesGcmHkdfStreamingParamsStruct> params_struct =
      FromParameters(parameters);
  if (!params_struct.ok()) {
    return params_struct.status();
  }
  AesGcmHkdfStreamingKeyFormatStruct format;
  format.version = 0;
  format.key_size = parameters.KeySizeInBytes();
  format.params = *params_struct;

  util::StatusOr<std::string> serialized =
      AesGcmHkdfStreamingKeyFormatStruct::Parser().SerializeIntoString(format);
  if (!serialized.ok()) {
    return serialized.status();
  }
  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixType::RAW, *serialized);
}

util::StatusOr<AesGcmHkdfStreamingKey> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required.");
  }
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesGcmHkdfStreamingKey.");
  }

  absl::StatusOr<AesGcmHkdfStreamingKeyStruct> parsed_key =
      AesGcmHkdfStreamingKeyStruct::Parser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!parsed_key.ok()) {
    return parsed_key.status();
  }

  if (parsed_key->version != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing AesGcmHkdfStreamingKey failed: only version 0 is accepted.");
  }

  util::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      ToParameters(parsed_key->params, parsed_key->key_value.size());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return AesGcmHkdfStreamingKey::Create(
      *parameters, RestrictedData(parsed_key->key_value, *token),
      GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const AesGcmHkdfStreamingKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required.");
  }
  util::StatusOr<RestrictedData> initial_key_material =
      key.GetInitialKeyMaterial(GetPartialKeyAccess());
  if (!initial_key_material.ok()) {
    return initial_key_material.status();
  }

  util::StatusOr<AesGcmHkdfStreamingParamsStruct> params_struct =
      FromParameters(key.GetParameters());
  if (!params_struct.ok()) {
    return params_struct.status();
  }
  AesGcmHkdfStreamingKeyStruct key_struct;
  key_struct.version = 0;
  key_struct.params = *params_struct;
  key_struct.key_value =
      util::SecretDataFromStringView(initial_key_material->GetSecret(*token));

  util::StatusOr<SecretData> serialized_key =
      AesGcmHkdfStreamingKeyStruct::Parser().SerializeIntoSecretData(
          key_struct);
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  return internal::ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(*std::move(serialized_key), *token),
      KeyData::SYMMETRIC, OutputPrefixType::RAW, key.GetIdRequirement());
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

util::Status RegisterAesGcmHkdfStreamingProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(AesGcmHkdfStreamingProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(
                   AesGcmHkdfStreamingProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(AesGcmHkdfStreamingProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(AesGcmHkdfStreamingProtoKeySerializer());
}

}  // namespace tink
}  // namespace crypto
