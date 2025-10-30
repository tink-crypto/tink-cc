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

#include "tink/daead/internal/aes_siv_proto_serialization_impl.h"

#include <array>
#include <cstdint>
#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/daead/aes_siv_key.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/daead/internal/aes_siv_proto_format.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/internal/proto_parser_secret_data_owning_field.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::OwningField;
using ::crypto::tink::internal::proto_parsing::SecretDataOwningField;
using ::crypto::tink::internal::proto_parsing::Uint32OwningField;

// Proto message com.google.crypto.tink.AesSivKey.
class ProtoAesSivKey : public Message<ProtoAesSivKey> {
 public:
  ProtoAesSivKey() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(SecretData key_value) {
    *key_value_.mutable_value() = std::move(key_value);
  }

  std::array<const OwningField*, 2> GetFields() const {
    return {&version_, &key_value_};
  }

 private:
  Uint32OwningField version_{1};
  SecretDataOwningField key_value_{2};
};

using AesSivProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, AesSivParameters>;
using AesSivProtoParametersSerializerImpl =
    ParametersSerializerImpl<AesSivParameters, ProtoParametersSerialization>;
using AesSivProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, AesSivKey>;
using AesSivProtoKeySerializerImpl =
    KeySerializerImpl<AesSivKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesSivKey";

absl::StatusOr<AesSivParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixTypeEnum::kCrunchy:
      return AesSivParameters::Variant::kCrunchy;
    case OutputPrefixTypeEnum::kRaw:
      return AesSivParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return AesSivParameters::Variant::kTink;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine AesSivParameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    AesSivParameters::Variant variant) {
  switch (variant) {
    case AesSivParameters::Variant::kCrunchy:
      return OutputPrefixTypeEnum::kCrunchy;
    case AesSivParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case AesSivParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

absl::StatusOr<AesSivParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetProtoKeyTemplate().type_url() != kTypeUrl) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesSivParameters.");
  }

  ProtoAesSivKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetProtoKeyTemplate().value())) {
    return absl::InvalidArgumentError("Failed to parse AesSivKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  absl::StatusOr<AesSivParameters::Variant> variant =
      ToVariant(serialization.GetProtoKeyTemplate().output_prefix_type());
  if (!variant.ok()) return variant.status();

  return AesSivParameters::Create(proto_key_format.key_size(), *variant);
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const AesSivParameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  ProtoAesSivKeyFormat proto_key_format;
  proto_key_format.set_key_size(parameters.KeySizeInBytes());
  proto_key_format.set_version(0);

  return ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

absl::StatusOr<AesSivKey> ParseKey(const ProtoKeySerialization& serialization,
                                   absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesSivKey.");
  }
  if (!token.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }
  ProtoAesSivKey proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse AesSivKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  absl::StatusOr<AesSivParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixTypeEnum());
  if (!variant.ok()) return variant.status();

  absl::StatusOr<AesSivParameters> parameters =
      AesSivParameters::Create(proto_key.key_value().size(), *variant);
  if (!parameters.ok()) return parameters.status();

  return AesSivKey::Create(
      *parameters, RestrictedData(proto_key.key_value(), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const AesSivKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) return restricted_input.status();
  if (!token.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }

  ProtoAesSivKey proto_key;
  proto_key.set_version(0);
  proto_key.set_key_value(restricted_input->Get(*token));

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  return ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(proto_key.SerializeAsSecretData(), *token),
      KeyMaterialTypeEnum::kSymmetric, *output_prefix_type,
      key.GetIdRequirement());
}

AesSivProtoParametersParserImpl* AesSivProtoParametersParser() {
  static auto* parser =
      new AesSivProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

AesSivProtoParametersSerializerImpl* AesSivProtoParametersSerializer() {
  static auto* serializer =
      new AesSivProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

AesSivProtoKeyParserImpl* AesSivProtoKeyParser() {
  static auto* parser = new AesSivProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesSivProtoKeySerializerImpl* AesSivProtoKeySerializer() {
  static auto* serializer = new AesSivProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterAesSivProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(AesSivProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      registry.RegisterParametersSerializer(AesSivProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(AesSivProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(AesSivProtoKeySerializer());
}

absl::Status RegisterAesSivProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(AesSivProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      builder.RegisterParametersSerializer(AesSivProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(AesSivProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(AesSivProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
