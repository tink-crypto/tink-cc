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

#include "tink/aead/internal/chacha20_poly1305_proto_serialization_impl.h"

#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/chacha20_poly1305_key.h"
#include "tink/aead/chacha20_poly1305_parameters.h"
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
#include "proto/chacha20_poly1305.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::ChaCha20Poly1305KeyFormat;
using ::google::crypto::tink::OutputPrefixType;

using ChaCha20Poly1305ProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   ChaCha20Poly1305Parameters>;
using ChaCha20Poly1305ProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<ChaCha20Poly1305Parameters,
                                       internal::ProtoParametersSerialization>;
using ChaCha20Poly1305ProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            ChaCha20Poly1305Key>;
using ChaCha20Poly1305ProtoKeySerializerImpl =
    internal::KeySerializerImpl<ChaCha20Poly1305Key,
                                internal::ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key";

util::StatusOr<ChaCha20Poly1305Parameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixType::CRUNCHY:
      return ChaCha20Poly1305Parameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return ChaCha20Poly1305Parameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return ChaCha20Poly1305Parameters::Variant::kTink;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine ChaCha20Poly1305Parameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    ChaCha20Poly1305Parameters::Variant variant) {
  switch (variant) {
    case ChaCha20Poly1305Parameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case ChaCha20Poly1305Parameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case ChaCha20Poly1305Parameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<ChaCha20Poly1305Parameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing ChaCha20Poly1305Parameters.");
  }

  ChaCha20Poly1305KeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse ChaCha20Poly1305KeyFormat proto");
  }

  util::StatusOr<ChaCha20Poly1305Parameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) return variant.status();

  return ChaCha20Poly1305Parameters::Create(*variant);
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const ChaCha20Poly1305Parameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type,
      ChaCha20Poly1305KeyFormat().SerializeAsString());
}

util::StatusOr<ChaCha20Poly1305Key> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing ChaCha20Poly1305Key.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }
  util::StatusOr<SecretProto<google::crypto::tink::ChaCha20Poly1305Key>>
      proto_key = SecretProto<google::crypto::tink::ChaCha20Poly1305Key>::
          ParseFromSecretData(serialization.SerializedKeyProto().Get(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse ChaCha20Poly1305Key proto");
  }
  if ((*proto_key)->version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<ChaCha20Poly1305Parameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) return variant.status();

  util::StatusOr<ChaCha20Poly1305Parameters> parameters =
      ChaCha20Poly1305Parameters::Create(*variant);
  if (!parameters.ok()) return parameters.status();

  return ChaCha20Poly1305Key::Create(
      parameters->GetVariant(),
      RestrictedData((*proto_key)->key_value(), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const ChaCha20Poly1305Key& key,
    absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) return restricted_input.status();
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }

  SecretProto<google::crypto::tink::ChaCha20Poly1305Key> proto_key;
  proto_key->set_version(0);
  internal::CallWithCoreDumpProtection(
      [&]() { proto_key->set_key_value(restricted_input->GetSecret(*token)); });

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  util::StatusOr<SecretData> serialized_key = proto_key.SerializeAsSecretData();
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*std::move(serialized_key), *token);

  return internal::ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, google::crypto::tink::KeyData::SYMMETRIC,
      *output_prefix_type, key.GetIdRequirement());
}

ChaCha20Poly1305ProtoParametersParserImpl*
ChaCha20Poly1305ProtoParametersParser() {
  static auto* parser =
      new ChaCha20Poly1305ProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

ChaCha20Poly1305ProtoParametersSerializerImpl*
ChaCha20Poly1305ProtoParametersSerializer() {
  static auto* serializer = new ChaCha20Poly1305ProtoParametersSerializerImpl(
      kTypeUrl, SerializeParameters);
  return serializer;
}

ChaCha20Poly1305ProtoKeyParserImpl* ChaCha20Poly1305ProtoKeyParser() {
  static auto* parser =
      new ChaCha20Poly1305ProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

ChaCha20Poly1305ProtoKeySerializerImpl* ChaCha20Poly1305ProtoKeySerializer() {
  static auto* serializer =
      new ChaCha20Poly1305ProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

util::Status RegisterChaCha20Poly1305ProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  util::Status status = registry.RegisterParametersParser(
      ChaCha20Poly1305ProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      ChaCha20Poly1305ProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(ChaCha20Poly1305ProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(ChaCha20Poly1305ProtoKeySerializer());
}

util::Status RegisterChaCha20Poly1305ProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  util::Status status =
      builder.RegisterParametersParser(ChaCha20Poly1305ProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterParametersSerializer(
      ChaCha20Poly1305ProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(ChaCha20Poly1305ProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(ChaCha20Poly1305ProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
