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

#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/chacha20_poly1305_key.h"
#include "tink/aead/chacha20_poly1305_parameters.h"
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

struct ChaCha20Poly1305KeyFormatStruct {
  static const ProtoParser<ChaCha20Poly1305KeyFormatStruct>& GetParser() {
    static const absl::NoDestructor<
        ProtoParser<ChaCha20Poly1305KeyFormatStruct>>
        parser(
            ProtoParserBuilder<ChaCha20Poly1305KeyFormatStruct>().BuildOrDie());
    return *parser;
  }
};

struct ChaCha20Poly1305KeyStruct {
  uint32_t version;
  util::SecretData key_value;

  static const ProtoParser<ChaCha20Poly1305KeyStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<ChaCha20Poly1305KeyStruct>>
        parser(ProtoParserBuilder<ChaCha20Poly1305KeyStruct>()
                   .AddUint32Field(1, &ChaCha20Poly1305KeyStruct::version)
                   .AddBytesSecretDataField(
                       2, &ChaCha20Poly1305KeyStruct::key_value)
                   .BuildOrDie());
    return *parser;
  }
};

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key";

absl::StatusOr<ChaCha20Poly1305Parameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixTypeEnum::kCrunchy:
      return ChaCha20Poly1305Parameters::Variant::kCrunchy;
    case OutputPrefixTypeEnum::kRaw:
      return ChaCha20Poly1305Parameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return ChaCha20Poly1305Parameters::Variant::kTink;
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine ChaCha20Poly1305Parameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    ChaCha20Poly1305Parameters::Variant variant) {
  switch (variant) {
    case ChaCha20Poly1305Parameters::Variant::kCrunchy:
      return OutputPrefixTypeEnum::kCrunchy;
    case ChaCha20Poly1305Parameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case ChaCha20Poly1305Parameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

absl::StatusOr<ChaCha20Poly1305Parameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing ChaCha20Poly1305Parameters.");
  }

  absl::StatusOr<ChaCha20Poly1305KeyFormatStruct> proto_key_format =
      ChaCha20Poly1305KeyFormatStruct::GetParser().Parse(
          serialization.GetKeyTemplate().value());
  if (!proto_key_format.ok()) {
    return absl::InvalidArgumentError(
        "Failed to parse ChaCha20Poly1305KeyFormat proto");
  }
  absl::StatusOr<ChaCha20Poly1305Parameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplateStruct().output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  return ChaCha20Poly1305Parameters::Create(*variant);
}

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const ChaCha20Poly1305Parameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  absl::StatusOr<std::string> serialized_key_format =
      ChaCha20Poly1305KeyFormatStruct::GetParser().SerializeIntoString(
          ChaCha20Poly1305KeyFormatStruct{});
  if (!serialized_key_format.ok()) {
    return serialized_key_format.status();
  }

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, *serialized_key_format);
}

absl::StatusOr<ChaCha20Poly1305Key> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing ChaCha20Poly1305Key.");
  }
  if (!token.has_value()) {
    return absl::InvalidArgumentError("SecretKeyAccess is required");
  }

  absl::StatusOr<ChaCha20Poly1305KeyStruct> key =
      ChaCha20Poly1305KeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!key.ok()) {
    return absl::InvalidArgumentError(
        "Failed to parse ChaCha20Poly1305Key proto");
  }
  if (key->version != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }
  absl::StatusOr<ChaCha20Poly1305Parameters::Variant> variant = ToVariant(
      static_cast<OutputPrefixTypeEnum>(serialization.GetOutputPrefixType()));
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<ChaCha20Poly1305Parameters> parameters =
      ChaCha20Poly1305Parameters::Create(*variant);
  if (!parameters.ok()) return parameters.status();

  return ChaCha20Poly1305Key::Create(
      parameters->GetVariant(), RestrictedData(key->key_value, *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const ChaCha20Poly1305Key& key,
    absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) return restricted_input.status();
  if (!token.has_value()) {
    return absl::InvalidArgumentError("SecretKeyAccess is required");
  }

  ChaCha20Poly1305KeyStruct key_struct;
  key_struct.version = 0;
  key_struct.key_value = restricted_input->Get(*token);

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  absl::StatusOr<SecretData> serialized_key =
      ChaCha20Poly1305KeyStruct::GetParser().SerializeIntoSecretData(
          key_struct);
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  return internal::ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(*std::move(serialized_key), *token),
      KeyMaterialTypeEnum::kSymmetric, *output_prefix_type,
      key.GetIdRequirement());
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

absl::Status RegisterChaCha20Poly1305ProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status = registry.RegisterParametersParser(
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

absl::Status RegisterChaCha20Poly1305ProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
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
