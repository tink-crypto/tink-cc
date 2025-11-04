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

#include "tink/mac/internal/aes_cmac_proto_serialization_impl.h"

#include <array>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/nullability.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
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
#include "tink/mac/aes_cmac_key.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"

ABSL_POINTERS_DEFAULT_NONNULL

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageOwningField;
using ::crypto::tink::internal::proto_parsing::OwningField;
using ::crypto::tink::internal::proto_parsing::SecretDataOwningField;
using ::crypto::tink::internal::proto_parsing::Uint32OwningField;

// Corresponds to google.crypto.tink.AesCmacKeyFormat.
class AesCmacParamProto : public Message<AesCmacParamProto> {
 public:
  uint32_t tag_size() const { return tag_size_.value(); }
  void set_tag_size(uint32_t value) { tag_size_.set_value(value); }

  std::array<const OwningField*, 1> GetFields() const {
    return std::array<const OwningField*, 1>{&tag_size_};
  }

 private:
  Uint32OwningField tag_size_{1};
};

// Corresponds to google.crypto.tink.AesCmacKey.
class AesCmacKeyProto : public Message<AesCmacKeyProto> {
 public:
  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(absl::string_view value) {
    *key_value_.mutable_value() = util::SecretDataFromStringView(value);
  }

  const AesCmacParamProto& params() const { return params_.value(); }
  AesCmacParamProto* mutable_params() { return params_.mutable_value(); }

  std::array<const OwningField*, 3> GetFields() const {
    return std::array<const OwningField*, 3>{&version_, &key_value_, &params_};
  }

 private:
  Uint32OwningField version_{1};
  SecretDataOwningField key_value_{2};
  MessageOwningField<AesCmacParamProto> params_{3};
};

// Corresponds to google.crypto.tink.AesCmacKeyFormat.
class AesCmacKeyFormatProto : public Message<AesCmacKeyFormatProto> {
 public:
  uint32_t key_size() const { return key_size_.value(); }
  void set_key_size(uint32_t value) { key_size_.set_value(value); }

  const AesCmacParamProto& params() const { return params_.value(); }
  AesCmacParamProto* mutable_params() { return params_.mutable_value(); }

  // This is safe because format doesn't contain any secret data.
  using Message::SerializeAsString;

  std::array<const OwningField*, 2> GetFields() const {
    return std::array<const OwningField*, 2>{&key_size_, &params_};
  }

 private:
  Uint32OwningField key_size_{1};
  MessageOwningField<AesCmacParamProto> params_{2};
};

using AesCmacProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, AesCmacParameters>;
using AesCmacProtoParametersSerializerImpl =
    ParametersSerializerImpl<AesCmacParameters, ProtoParametersSerialization>;
using AesCmacProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, AesCmacKey>;
using AesCmacProtoKeySerializerImpl =
    KeySerializerImpl<AesCmacKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCmacKey";

absl::StatusOr<AesCmacParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kCrunchy:
      return AesCmacParameters::Variant::kCrunchy;
    case OutputPrefixTypeEnum::kLegacy:
      return AesCmacParameters::Variant::kLegacy;
    case OutputPrefixTypeEnum::kRaw:
      return AesCmacParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return AesCmacParameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine AesCmacParameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    AesCmacParameters::Variant variant) {
  switch (variant) {
    case AesCmacParameters::Variant::kCrunchy:
      return OutputPrefixTypeEnum::kCrunchy;
    case AesCmacParameters::Variant::kLegacy:
      return OutputPrefixTypeEnum::kLegacy;
    case AesCmacParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case AesCmacParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

absl::StatusOr<AesCmacParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesCmacParameters.");
  }

  AesCmacKeyFormatProto proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError(
        "Failed to parse AesCmacKeyFormatProto from string.");
  }
  absl::StatusOr<AesCmacParameters::Variant> variant =
      ToVariant(key_template.output_prefix_type());
  if (!variant.ok()) {
    return variant.status();
  }
  return AesCmacParameters::Create(proto_key_format.key_size(),
                                   proto_key_format.params().tag_size(),
                                   *variant);
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const AesCmacParameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  AesCmacKeyFormatProto proto_key_format;
  proto_key_format.set_key_size(parameters.KeySizeInBytes());
  proto_key_format.mutable_params()->set_tag_size(
      parameters.CryptographicTagSizeInBytes());

  std::string serialized = proto_key_format.SerializeAsString();
  return ProtoParametersSerialization::Create(kTypeUrl, *output_prefix_type,
                                              serialized);
}

absl::StatusOr<AesCmacKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesCmacKey.");
  }
  if (!token.has_value()) {
    return absl::InvalidArgumentError("SecretKeyAccess is required");
  }

  AesCmacKeyProto proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse AesCmacKey proto");
  }

  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<AesCmacParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixTypeEnum());
  if (!variant.ok()) return variant.status();

  absl::StatusOr<AesCmacParameters> parameters = AesCmacParameters::Create(
      proto_key.key_value().size(), proto_key.params().tag_size(), *variant);
  if (!parameters.ok()) return parameters.status();

  return AesCmacKey::Create(
      *parameters, RestrictedData(std::move(proto_key).key_value(), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const AesCmacKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) return restricted_input.status();
  if (!token.has_value()) {
    return absl::InvalidArgumentError("SecretKeyAccess is required");
  }

  AesCmacKeyProto proto_key;
  proto_key.mutable_params()->set_tag_size(
      key.GetParameters().CryptographicTagSizeInBytes());
  proto_key.set_version(0);
  proto_key.set_key_value(restricted_input->GetSecret(*token));

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  SecretData serialized_key = proto_key.SerializeAsSecretData();
  RestrictedData restricted_output =
      RestrictedData(std::move(serialized_key), *token);
  return ProtoKeySerialization::Create(
      kTypeUrl, std::move(restricted_output), KeyMaterialTypeEnum::kSymmetric,
      *output_prefix_type, key.GetIdRequirement());
}

AesCmacProtoParametersParserImpl* AesCmacProtoParametersParser() {
  static auto* parser =
      new AesCmacProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

AesCmacProtoParametersSerializerImpl* AesCmacProtoParametersSerializer() {
  static auto* serializer =
      new AesCmacProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

AesCmacProtoKeyParserImpl* AesCmacProtoKeyParser() {
  static auto* parser = new AesCmacProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesCmacProtoKeySerializerImpl* AesCmacProtoKeySerializer() {
  static auto* serializer = new AesCmacProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterAesCmacProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(AesCmacProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      registry.RegisterParametersSerializer(AesCmacProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(AesCmacProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(AesCmacProtoKeySerializer());
}

absl::Status RegisterAesCmacProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(AesCmacProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      builder.RegisterParametersSerializer(AesCmacProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(AesCmacProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(AesCmacProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
