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

#include "tink/aead/internal/aes_gcm_siv_proto_serialization_impl.h"

#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_siv_key.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_gcm_siv.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::AesGcmSivKeyFormat;
using ::google::crypto::tink::OutputPrefixType;

using AesGcmSivProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, AesGcmSivParameters>;
using AesGcmSivProtoParametersSerializerImpl =
    ParametersSerializerImpl<AesGcmSivParameters, ProtoParametersSerialization>;
using AesGcmSivProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, AesGcmSivKey>;
using AesGcmSivProtoKeySerializerImpl =
    KeySerializerImpl<AesGcmSivKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesGcmSivKey";

util::StatusOr<AesGcmSivParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixType::CRUNCHY:
      return AesGcmSivParameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return AesGcmSivParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return AesGcmSivParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine AesGcmSivParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    AesGcmSivParameters::Variant variant) {
  switch (variant) {
    case AesGcmSivParameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case AesGcmSivParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case AesGcmSivParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<AesGcmSivParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesGcmSivParameters.");
  }

  AesGcmSivKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesGcmSivKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<AesGcmSivParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) {
    return variant.status();
  }

  return AesGcmSivParameters::Create(proto_key_format.key_size(), *variant);
}

util::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const AesGcmSivParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  AesGcmSivKeyFormat proto_key_format;
  proto_key_format.set_version(0);
  proto_key_format.set_key_size(parameters.KeySizeInBytes());

  return ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

util::StatusOr<AesGcmSivKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesGcmSivKey.");
  }
  util::StatusOr<SecretProto<google::crypto::tink::AesGcmSivKey>> proto_key =
      SecretProto<google::crypto::tink::AesGcmSivKey>::ParseFromSecretData(
          serialization.SerializedKeyProto().Get(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesGcmSivKey proto");
  }
  if ((*proto_key)->version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<AesGcmSivParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<AesGcmSivParameters> parameters =
      AesGcmSivParameters::Create((*proto_key)->key_value().length(), *variant);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return AesGcmSivKey::Create(
      *parameters, RestrictedData((*proto_key)->key_value(), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

util::StatusOr<ProtoKeySerialization> SerializeKey(
    const AesGcmSivKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  util::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  SecretProto<google::crypto::tink::AesGcmSivKey> proto_key;
  proto_key->set_version(0);
  CallWithCoreDumpProtection(
      [&]() { proto_key->set_key_value(restricted_input->GetSecret(*token)); });

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<SecretData> serialized_key = proto_key.SerializeAsSecretData();
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*std::move(serialized_key), *token);
  return ProtoKeySerialization::Create(kTypeUrl, std::move(restricted_output),
                                       google::crypto::tink::KeyData::SYMMETRIC,
                                       *output_prefix_type,
                                       key.GetIdRequirement());
}

AesGcmSivProtoParametersParserImpl* AesGcmSivProtoParametersParser() {
  static auto* parser =
      new AesGcmSivProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

AesGcmSivProtoParametersSerializerImpl* AesGcmSivProtoParametersSerializer() {
  static auto* serializer =
      new AesGcmSivProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

AesGcmSivProtoKeyParserImpl* AesGcmSivProtoKeyParser() {
  static auto* parser = new AesGcmSivProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesGcmSivProtoKeySerializerImpl* AesGcmSivProtoKeySerializer() {
  static auto* serializer = new AesGcmSivProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

util::Status RegisterAesGcmSivProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  util::Status status =
      registry.RegisterParametersParser(AesGcmSivProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      AesGcmSivProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(AesGcmSivProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(AesGcmSivProtoKeySerializer());
}

util::Status RegisterAesGcmSivProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  util::Status status =
      builder.RegisterParametersParser(AesGcmSivProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterParametersSerializer(
      AesGcmSivProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(AesGcmSivProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(AesGcmSivProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
