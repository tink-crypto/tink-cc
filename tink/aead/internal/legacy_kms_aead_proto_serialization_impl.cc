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

#include "tink/aead/internal/legacy_kms_aead_proto_serialization_impl.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/legacy_kms_aead_key.h"
#include "tink/aead/legacy_kms_aead_parameters.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/kms_aead.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::util::SecretData;
using ::google::crypto::tink::KmsAeadKey;
using ::google::crypto::tink::KmsAeadKeyFormat;
using ::google::crypto::tink::OutputPrefixType;

using LegacyKmsAeadProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   LegacyKmsAeadParameters>;
using LegacyKmsAeadProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<LegacyKmsAeadParameters,
                                       internal::ProtoParametersSerialization>;
using LegacyKmsAeadProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, LegacyKmsAeadKey>;
using LegacyKmsAeadProtoKeySerializerImpl =
    internal::KeySerializerImpl<LegacyKmsAeadKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.KmsAeadKey";

util::StatusOr<LegacyKmsAeadParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::RAW:
      return LegacyKmsAeadParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return LegacyKmsAeadParameters::Variant::kTink;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine LegacyKmsAeadParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    LegacyKmsAeadParameters::Variant variant) {
  switch (variant) {
    case LegacyKmsAeadParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case LegacyKmsAeadParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<LegacyKmsAeadParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing LegacyKmsAeadParameters.");
  }

  KmsAeadKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse KmsAeadKeyFormat proto");
  }

  util::StatusOr<LegacyKmsAeadParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) {
    return variant.status();
  }

  return LegacyKmsAeadParameters::Create(proto_key_format.key_uri(), *variant);
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const LegacyKmsAeadParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  KmsAeadKeyFormat proto_key_format;
  proto_key_format.set_key_uri(parameters.GetKeyUri());

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

util::StatusOr<LegacyKmsAeadKey> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing LegacyKmsAeadKey.");
  }
  KmsAeadKey proto_key;
  if (!proto_key.ParseFromString(serialization.SerializedKeyProto().GetSecret(
          GetInsecureSecretKeyAccessInternal()))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse KmsAeadKey proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<LegacyKmsAeadParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(proto_key.params().key_uri(), *variant);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return LegacyKmsAeadKey::Create(*parameters, serialization.IdRequirement());
}

util::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const LegacyKmsAeadKey& key, absl::optional<SecretKeyAccessToken> token) {
  KmsAeadKeyFormat proto_key_format;
  proto_key_format.set_key_uri(key.GetParameters().GetKeyUri());
  KmsAeadKey proto_key;
  proto_key.set_version(0);
  *proto_key.mutable_params() = proto_key_format;

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output = RestrictedData(
      proto_key.SerializeAsString(), GetInsecureSecretKeyAccessInternal());

  return internal::ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, google::crypto::tink::KeyData::REMOTE,
      *output_prefix_type, key.GetIdRequirement());
}

LegacyKmsAeadProtoParametersParserImpl* LegacyKmsAeadProtoParametersParser() {
  static auto* parser =
      new LegacyKmsAeadProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

LegacyKmsAeadProtoParametersSerializerImpl*
LegacyKmsAeadProtoParametersSerializer() {
  static auto* serializer = new LegacyKmsAeadProtoParametersSerializerImpl(
      kTypeUrl, SerializeParameters);
  return serializer;
}

LegacyKmsAeadProtoKeyParserImpl* LegacyKmsAeadProtoKeyParser() {
  static auto* parser = new LegacyKmsAeadProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

LegacyKmsAeadProtoKeySerializerImpl* LegacyKmsAeadProtoKeySerializer() {
  static auto* serializer =
      new LegacyKmsAeadProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

util::Status RegisterLegacyKmsAeadProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  util::Status status =
      registry.RegisterParametersParser(LegacyKmsAeadProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      LegacyKmsAeadProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(LegacyKmsAeadProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(LegacyKmsAeadProtoKeySerializer());
}

util::Status RegisterLegacyKmsAeadProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  util::Status status =
      builder.RegisterParametersParser(LegacyKmsAeadProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterParametersSerializer(
      LegacyKmsAeadProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(LegacyKmsAeadProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(LegacyKmsAeadProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
