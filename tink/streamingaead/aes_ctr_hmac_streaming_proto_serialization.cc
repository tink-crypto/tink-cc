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

#include "tink/streamingaead/aes_ctr_hmac_streaming_proto_serialization.h"

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
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
#include "tink/streamingaead/aes_ctr_hmac_streaming_key.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_ctr_hmac_streaming.pb.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::util::SecretData;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;

struct HmacParamsStruct {
  google::crypto::tink::HashType hash;
  uint32_t tag_size;

  static internal::ProtoParser<HmacParamsStruct> CreateParser() {
    return internal::ProtoParserBuilder<HmacParamsStruct>()
        .AddEnumField(
            1, &HmacParamsStruct::hash,
            +[](uint32_t hash_type) {
              return google::crypto::tink::HashType_IsValid(hash_type);
            })
        .AddUint32Field(2, &HmacParamsStruct::tag_size)
        .BuildOrDie();
  }
};

struct AesCtrHmacStreamingParamsStruct {
  uint32_t ciphertext_segment_size;
  uint32_t derived_key_size;
  google::crypto::tink::HashType hkdf_hash_type;
  HmacParamsStruct hmac_params;

  static internal::ProtoParser<AesCtrHmacStreamingParamsStruct> CreateParser() {
    return internal::ProtoParserBuilder<AesCtrHmacStreamingParamsStruct>()
        .AddUint32Field(
            1, &AesCtrHmacStreamingParamsStruct::ciphertext_segment_size)
        .AddUint32Field(2, &AesCtrHmacStreamingParamsStruct::derived_key_size)
        .AddEnumField(
            3, &AesCtrHmacStreamingParamsStruct::hkdf_hash_type,
            +[](uint32_t hash_type) {
              return google::crypto::tink::HashType_IsValid(hash_type);
            })
        .AddMessageField(4, &AesCtrHmacStreamingParamsStruct::hmac_params,
                         HmacParamsStruct::CreateParser())
        .BuildOrDie();
  }
};

struct AesCtrHmacStreamingKeyFormatStruct {
  uint32_t version;
  AesCtrHmacStreamingParamsStruct params;
  uint32_t key_size;

  static internal::ProtoParser<AesCtrHmacStreamingKeyFormatStruct>
  CreateParser() {
    return internal::ProtoParserBuilder<AesCtrHmacStreamingKeyFormatStruct>()
        .AddUint32Field(3, &AesCtrHmacStreamingKeyFormatStruct::version)
        .AddMessageField(1, &AesCtrHmacStreamingKeyFormatStruct::params,
                         AesCtrHmacStreamingParamsStruct::CreateParser())
        .AddUint32Field(2, &AesCtrHmacStreamingKeyFormatStruct::key_size)
        .BuildOrDie();
  }

  static const internal::ProtoParser<AesCtrHmacStreamingKeyFormatStruct>&
  Parser() {
    static absl::NoDestructor<
        internal::ProtoParser<AesCtrHmacStreamingKeyFormatStruct>>
        parser{AesCtrHmacStreamingKeyFormatStruct::CreateParser()};
    return *parser;
  }
};

struct AesCtrHmacStreamingKeyStruct {
  uint32_t version;
  AesCtrHmacStreamingParamsStruct params;
  SecretData key_value;

  static internal::ProtoParser<AesCtrHmacStreamingKeyStruct> CreateParser() {
    return internal::ProtoParserBuilder<AesCtrHmacStreamingKeyStruct>()
        .AddUint32Field(1, &AesCtrHmacStreamingKeyStruct::version)
        .AddMessageField(2, &AesCtrHmacStreamingKeyStruct::params,
                         AesCtrHmacStreamingParamsStruct::CreateParser())
        .AddBytesSecretDataField(3, &AesCtrHmacStreamingKeyStruct::key_value)
        .BuildOrDie();
  }

  static const internal::ProtoParser<AesCtrHmacStreamingKeyStruct>& Parser() {
    static absl::NoDestructor<
        internal::ProtoParser<AesCtrHmacStreamingKeyStruct>>
        parser{AesCtrHmacStreamingKeyStruct::CreateParser()};
    return *parser;
  }
};

using AesCtrHmacStreamingProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   AesCtrHmacStreamingParameters>;
using AesCtrHmacStreamingProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<AesCtrHmacStreamingParameters,
                                       internal::ProtoParametersSerialization>;
using AesCtrHmacStreamingProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            AesCtrHmacStreamingKey>;
using AesCtrHmacStreamingProtoKeySerializerImpl =
    internal::KeySerializerImpl<AesCtrHmacStreamingKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";

util::StatusOr<AesCtrHmacStreamingParameters::HashType> FromProtoHashType(
    google::crypto::tink::HashType hash_type) {
  switch (hash_type) {
    case google::crypto::tink::HashType::SHA1:
      return AesCtrHmacStreamingParameters::HashType::kSha1;
    case google::crypto::tink::HashType::SHA256:
      return AesCtrHmacStreamingParameters::HashType::kSha256;
    case google::crypto::tink::HashType::SHA512:
      return AesCtrHmacStreamingParameters::HashType::kSha512;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported proto hash type: ",
                       google::crypto::tink::HashType_Name(hash_type)));
  }
}

util::StatusOr<google::crypto::tink::HashType> ToProtoHashType(
    AesCtrHmacStreamingParameters::HashType hash_type) {
  switch (hash_type) {
    case AesCtrHmacStreamingParameters::HashType::kSha1:
      return google::crypto::tink::HashType::SHA1;
    case AesCtrHmacStreamingParameters::HashType::kSha256:
      return google::crypto::tink::HashType::SHA256;
    case AesCtrHmacStreamingParameters::HashType::kSha512:
      return google::crypto::tink::HashType::SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported hash type: ", hash_type));
  }
}

util::StatusOr<AesCtrHmacStreamingParameters> ToParameters(
    const AesCtrHmacStreamingParamsStruct& params_struct, int key_size) {
  util::StatusOr<AesCtrHmacStreamingParameters::HashType> hkdf_hash_type =
      FromProtoHashType(params_struct.hkdf_hash_type);
  if (!hkdf_hash_type.ok()) {
    return hkdf_hash_type.status();
  }
  util::StatusOr<AesCtrHmacStreamingParameters::HashType> hmac_hash_type =
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

util::StatusOr<AesCtrHmacStreamingParamsStruct> FromParameters(
    const AesCtrHmacStreamingParameters& parameters) {
  util::StatusOr<google::crypto::tink::HashType> hkdf_hash_type =
      ToProtoHashType(parameters.HkdfHashType());
  if (!hkdf_hash_type.ok()) {
    return hkdf_hash_type.status();
  }
  util::StatusOr<google::crypto::tink::HashType> hmac_hash_type =
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

util::StatusOr<AesCtrHmacStreamingParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing AesCtrHmacStreamingParameters.");
  }
  util::StatusOr<AesCtrHmacStreamingKeyFormatStruct> key_format_struct =
      AesCtrHmacStreamingKeyFormatStruct::Parser().Parse(
          serialization.GetKeyTemplate().value());
  if (!key_format_struct.ok()) {
    return key_format_struct.status();
  }
  if (key_format_struct->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Parsing AesCtrHmacStreamingKeyFormat failed: only "
                        "version 0 is accepted.");
  }
  return ToParameters(key_format_struct->params, key_format_struct->key_size);
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const AesCtrHmacStreamingParameters& parameters) {
  util::StatusOr<AesCtrHmacStreamingParamsStruct> params_struct =
      FromParameters(parameters);
  if (!params_struct.ok()) {
    return params_struct.status();
  }
  AesCtrHmacStreamingKeyFormatStruct format;
  format.version = 0;
  format.key_size = parameters.KeySizeInBytes();
  format.params = *params_struct;

  util::StatusOr<std::string> serialized_format =
      AesCtrHmacStreamingKeyFormatStruct::Parser().SerializeIntoString(format);
  if (!serialized_format.ok()) {
    return serialized_format.status();
  }

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixType::RAW, *serialized_format);
}

util::StatusOr<AesCtrHmacStreamingKey> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required.");
  }
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesCtrHmacStreamingKey.");
  }

  util::StatusOr<AesCtrHmacStreamingKeyStruct> parsed_key_struct =
      AesCtrHmacStreamingKeyStruct::Parser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!parsed_key_struct.ok()) {
    return parsed_key_struct.status();
  }

  if (parsed_key_struct->version != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing AesCtrHmacStreamingKey failed: only version 0 is accepted.");
  }

  util::StatusOr<AesCtrHmacStreamingParameters> parameters = ToParameters(
      parsed_key_struct->params, parsed_key_struct->key_value.size());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return AesCtrHmacStreamingKey::Create(
      *parameters, RestrictedData(parsed_key_struct->key_value, *token),
      GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const AesCtrHmacStreamingKey& key,
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
  util::StatusOr<AesCtrHmacStreamingParamsStruct> params_struct =
      FromParameters(key.GetParameters());
  if (!params_struct.ok()) {
    return params_struct.status();
  }

  AesCtrHmacStreamingKeyStruct key_struct;
  key_struct.version = 0;
  key_struct.params = *params_struct;
  key_struct.key_value =
      util::SecretDataFromStringView(initial_key_material->GetSecret(*token));

  util::StatusOr<SecretData> serialized_key =
      AesCtrHmacStreamingKeyStruct::Parser().SerializeIntoSecretData(
          key_struct);
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  return internal::ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(*std::move(serialized_key), *token),
      KeyData::SYMMETRIC, OutputPrefixType::RAW, key.GetIdRequirement());
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

util::Status RegisterAesCtrHmacStreamingProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(AesCtrHmacStreamingProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(
                   AesCtrHmacStreamingProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(AesCtrHmacStreamingProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(AesCtrHmacStreamingProtoKeySerializer());
}

}  // namespace tink
}  // namespace crypto
