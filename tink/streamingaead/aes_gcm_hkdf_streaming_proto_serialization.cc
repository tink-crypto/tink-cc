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

#include <new>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_gcm_hkdf_streaming.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::AesGcmHkdfStreamingKeyFormat;
using ::google::crypto::tink::AesGcmHkdfStreamingParams;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;

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

util::StatusOr<AesGcmHkdfStreamingParameters> FromProtoParams(
    const AesGcmHkdfStreamingParams& proto_params, int key_size) {
  util::StatusOr<AesGcmHkdfStreamingParameters::HashType> hash_type =
      FromProtoHashType(proto_params.hkdf_hash_type());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  return AesGcmHkdfStreamingParameters::Builder()
      .SetKeySizeInBytes(key_size)
      .SetDerivedKeySizeInBytes(proto_params.derived_key_size())
      .SetHashType(*hash_type)
      .SetCiphertextSegmentSizeInBytes(proto_params.ciphertext_segment_size())
      .Build();
}

util::StatusOr<AesGcmHkdfStreamingParams> ToProtoParams(
    const AesGcmHkdfStreamingParameters& parameters) {
  util::StatusOr<google::crypto::tink::HashType> hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  AesGcmHkdfStreamingParams params;
  params.set_derived_key_size(parameters.DerivedKeySizeInBytes());
  params.set_hkdf_hash_type(*hash_type);
  params.set_ciphertext_segment_size(parameters.CiphertextSegmentSizeInBytes());
  return params;
}

util::StatusOr<AesGcmHkdfStreamingParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing AesGcmHkdfStreamingParameters.");
  }
  AesGcmHkdfStreamingKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesGcmHkdfStreamingKeyFormat proto.");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Parsing AesGcmHkdfStreamingKeyFormat failed: only "
                        "version 0 is accepted.");
  }

  if (!proto_key_format.has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Missing AesGcmHkdfStreamingParams.");
  }
  return FromProtoParams(proto_key_format.params(),
                         proto_key_format.key_size());
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const AesGcmHkdfStreamingParameters& parameters) {
  AesGcmHkdfStreamingKeyFormat format;
  format.set_version(0);
  format.set_key_size(parameters.KeySizeInBytes());
  util::StatusOr<AesGcmHkdfStreamingParams> proto_params =
      ToProtoParams(parameters);
  if (!proto_params.ok()) {
    return proto_params.status();
  }
  *format.mutable_params() = *proto_params;

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixType::RAW, format.SerializeAsString());
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
  absl::StatusOr<SecretProto<google::crypto::tink::AesGcmHkdfStreamingKey>>
      proto_key = SecretProto<google::crypto::tink::AesGcmHkdfStreamingKey>::
          ParseFromSecretData(serialization.SerializedKeyProto().Get(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesGcmHkdfStreamingKey proto.");
  }
  if ((*proto_key)->version() != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing AesGcmHkdfStreamingKey failed: only version 0 is accepted.");
  }

  if (!(*proto_key)->has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Missing AesGcmHkdfStreamingParams.");
  }
  util::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      FromProtoParams((*proto_key)->params(), (*proto_key)->key_value().size());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return AesGcmHkdfStreamingKey::Create(
      *parameters, RestrictedData((*proto_key)->key_value(), *token),
      GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const AesGcmHkdfStreamingKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required.");
  }
  util::StatusOr<RestrictedData> restricted_input =
      key.GetInitialKeyMaterial(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }
  util::StatusOr<AesGcmHkdfStreamingParams> proto_params =
      ToProtoParams(key.GetParameters());
  if (!proto_params.ok()) {
    return proto_params.status();
  }

  SecretProto<google::crypto::tink::AesGcmHkdfStreamingKey> proto_key;
  proto_key->set_version(0);
  internal::CallWithCoreDumpProtection(
      [&]() { proto_key->set_key_value(restricted_input->GetSecret(*token)); });
  *proto_key->mutable_params() = *proto_params;

  util::StatusOr<SecretData> serialized_key = proto_key.SerializeAsSecretData();
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
