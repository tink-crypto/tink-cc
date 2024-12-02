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

#include "tink/signature/internal/ed25519_proto_serialization_impl.h"

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
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
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/ed25519.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::Ed25519KeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;

using Ed25519ProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, Ed25519Parameters>;
using Ed25519ProtoParametersSerializerImpl =
    ParametersSerializerImpl<Ed25519Parameters, ProtoParametersSerialization>;
using Ed25519ProtoPublicKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, Ed25519PublicKey>;
using Ed25519ProtoPublicKeySerializerImpl =
    KeySerializerImpl<Ed25519PublicKey, ProtoKeySerialization>;
using Ed25519ProtoPrivateKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, Ed25519PrivateKey>;
using Ed25519ProtoPrivateKeySerializerImpl =
    KeySerializerImpl<Ed25519PrivateKey, ProtoKeySerialization>;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.Ed25519PublicKey";
const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";

util::StatusOr<Ed25519Parameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      return Ed25519Parameters::Variant::kLegacy;
    case OutputPrefixType::CRUNCHY:
      return Ed25519Parameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return Ed25519Parameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return Ed25519Parameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine Ed25519Parameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    Ed25519Parameters::Variant variant) {
  switch (variant) {
    case Ed25519Parameters::Variant::kLegacy:
      return OutputPrefixType::LEGACY;
    case Ed25519Parameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case Ed25519Parameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case Ed25519Parameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<Ed25519Parameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing Ed25519Parameters.");
  }

  Ed25519KeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse Ed25519KeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<Ed25519Parameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) {
    return variant.status();
  }

  return Ed25519Parameters::Create(*variant);
}

util::StatusOr<Ed25519PublicKey> ParsePublicKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing Ed25519PublicKey.");
  }

  google::crypto::tink::Ed25519PublicKey proto_key;
  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  if (!proto_key.ParseFromString(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse Ed25519PublicKey proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<Ed25519Parameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(*variant);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return Ed25519PublicKey::Create(*parameters, proto_key.key_value(),
                                  serialization.IdRequirement(),
                                  GetPartialKeyAccess());
}

util::StatusOr<Ed25519PrivateKey> ParsePrivateKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing Ed25519PrivateKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  absl::StatusOr<SecretProto<google::crypto::tink::Ed25519PrivateKey>>
      proto_key = SecretProto<google::crypto::tink::Ed25519PrivateKey>::
          ParseFromSecretData(serialization.SerializedKeyProto().Get(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse Ed25519PrivateKey proto");
  }
  if ((*proto_key)->version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }
  if ((*proto_key)->public_key().version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 public keys are accepted.");
  }

  util::StatusOr<Ed25519Parameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(*variant);
  if (!parameters.ok()) {
    return parameters.status();
  }

  util::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *parameters, (*proto_key)->public_key().key_value(),
      serialization.IdRequirement(), GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return Ed25519PrivateKey::Create(
      *public_key, RestrictedData((*proto_key)->key_value(), *token),
      GetPartialKeyAccess());
}

util::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const Ed25519Parameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  Ed25519KeyFormat proto_key_format;
  proto_key_format.set_version(0);

  return ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type,
      proto_key_format.SerializeAsString());
}

util::StatusOr<ProtoKeySerialization> SerializePublicKey(
    const Ed25519PublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  google::crypto::tink::Ed25519PublicKey proto_key;
  proto_key.set_version(0);
  proto_key.set_key_value(key.GetPublicKeyBytes(GetPartialKeyAccess()));

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output = RestrictedData(
      proto_key.SerializeAsString(), InsecureSecretKeyAccess::Get());
  return ProtoKeySerialization::Create(
      kPublicTypeUrl, restricted_output, KeyData::ASYMMETRIC_PUBLIC,
      *output_prefix_type, key.GetIdRequirement());
}

util::StatusOr<ProtoKeySerialization> SerializePrivateKey(
    const Ed25519PrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<RestrictedData> restricted_input =
      key.GetPrivateKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  google::crypto::tink::Ed25519PublicKey proto_public_key;
  proto_public_key.set_version(0);
  proto_public_key.set_key_value(
      key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess()));

  SecretProto<google::crypto::tink::Ed25519PrivateKey> proto_private_key;
  proto_private_key->set_version(0);
  *proto_private_key->mutable_public_key() = proto_public_key;
  CallWithCoreDumpProtection([&] {
    proto_private_key->set_key_value(
        util::SecretDataAsStringView(restricted_input->Get(*token)));
  });

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<util::SecretData> proto_private_key_secret_data =
      proto_private_key.SerializeAsSecretData();
  if (!proto_private_key_secret_data.ok()) {
    return proto_private_key_secret_data.status();
  }
  return ProtoKeySerialization::Create(
      kPrivateTypeUrl,
      RestrictedData(*std::move(proto_private_key_secret_data), *token),
      KeyData::ASYMMETRIC_PRIVATE, *output_prefix_type, key.GetIdRequirement());
}

Ed25519ProtoParametersParserImpl* Ed25519ProtoParametersParser() {
  static auto* parser =
      new Ed25519ProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return parser;
}

Ed25519ProtoParametersSerializerImpl* Ed25519ProtoParametersSerializer() {
  static auto* serializer = new Ed25519ProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return serializer;
}

Ed25519ProtoPublicKeyParserImpl* Ed25519ProtoPublicKeyParser() {
  static auto* parser =
      new Ed25519ProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return parser;
}

Ed25519ProtoPublicKeySerializerImpl* Ed25519ProtoPublicKeySerializer() {
  static auto* serializer =
      new Ed25519ProtoPublicKeySerializerImpl(SerializePublicKey);
  return serializer;
}

Ed25519ProtoPrivateKeyParserImpl* Ed25519ProtoPrivateKeyParser() {
  static auto* parser =
      new Ed25519ProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return parser;
}

Ed25519ProtoPrivateKeySerializerImpl* Ed25519ProtoPrivateKeySerializer() {
  static auto* serializer =
      new Ed25519ProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return serializer;
}

}  // namespace

util::Status RegisterEd25519ProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  util::Status status =
      registry.RegisterParametersParser(Ed25519ProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      registry.RegisterParametersSerializer(Ed25519ProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(Ed25519ProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeySerializer(Ed25519ProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(Ed25519ProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(Ed25519ProtoPrivateKeySerializer());
}

util::Status RegisterEd25519ProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  util::Status status =
      builder.RegisterParametersParser(Ed25519ProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      builder.RegisterParametersSerializer(Ed25519ProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(Ed25519ProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeySerializer(Ed25519ProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(Ed25519ProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(Ed25519ProtoPrivateKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto