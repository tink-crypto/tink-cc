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

#include <array>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
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
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::BytesField;
using ::crypto::tink::internal::proto_parsing::Field;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageField;
using ::crypto::tink::internal::proto_parsing::Uint32Field;

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

class KmsAeadKeyFormatTP : public Message {
 public:
  KmsAeadKeyFormatTP() = default;

  const std::string& key_uri() const { return key_uri_.value(); }
  void set_key_uri(absl::string_view value) { key_uri_.set_value(value); }

  // This is OK because this class doesn't contain secret data.
  using Message::SerializeAsString;

 private:
  size_t num_fields() const override { return 1; }
  const Field* field(int i) const override {
    return std::array<const Field*, 1>{&key_uri_}[i];
  }
  BytesField key_uri_{1};
};

class KmsAeadKeyTP : public Message {
 public:
  KmsAeadKeyTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const KmsAeadKeyFormatTP& params() const { return params_.value(); }
  KmsAeadKeyFormatTP* mutable_params() { return params_.mutable_value(); }

 private:
  size_t num_fields() const override { return 2; }
  const Field* field(int i) const override {
    return std::array<const Field*, 2>{&version_, &params_}[i];
  }
  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  MessageField<KmsAeadKeyFormatTP> params_{2};
};

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.KmsAeadKey";

absl::StatusOr<LegacyKmsAeadParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kRaw:
      return LegacyKmsAeadParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return LegacyKmsAeadParameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine LegacyKmsAeadParameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    LegacyKmsAeadParameters::Variant variant) {
  switch (variant) {
    case LegacyKmsAeadParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case LegacyKmsAeadParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

absl::StatusOr<LegacyKmsAeadParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  const KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing LegacyKmsAeadParameters.");
  }
  KmsAeadKeyFormatTP key_format;
  if (!key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError("Failed to parse KmsAeadKeyFormat proto");
  }
  absl::StatusOr<LegacyKmsAeadParameters::Variant> variant =
      ToVariant(key_template.output_prefix_type());
  if (!variant.ok()) {
    return variant.status();
  }
  return LegacyKmsAeadParameters::Create(key_format.key_uri(), *variant);
}

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const LegacyKmsAeadParameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  KmsAeadKeyFormatTP key_format;
  key_format.set_key_uri(parameters.GetKeyUri());

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, key_format.SerializeAsString());
}

absl::StatusOr<LegacyKmsAeadKey> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing LegacyKmsAeadKey.");
  }
  KmsAeadKeyTP proto_key;
  if (!proto_key.ParseFromString(serialization.SerializedKeyProto().GetSecret(
          GetInsecureSecretKeyAccessInternal()))) {
    return absl::InvalidArgumentError("Failed to parse KmsAeadKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<LegacyKmsAeadParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixTypeEnum());
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(proto_key.params().key_uri(), *variant);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return LegacyKmsAeadKey::Create(*parameters, serialization.IdRequirement());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const LegacyKmsAeadKey& key, absl::optional<SecretKeyAccessToken> token) {
  KmsAeadKeyTP proto_key;
  proto_key.set_version(0);
  proto_key.mutable_params()->set_key_uri(key.GetParameters().GetKeyUri());

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  SecretData serialized_key = proto_key.SerializeAsSecretData();

  RestrictedData restricted_output = RestrictedData(
      std::move(serialized_key), GetInsecureSecretKeyAccessInternal());

  return internal::ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, KeyMaterialTypeEnum::kRemote,
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

absl::Status RegisterLegacyKmsAeadProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
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

absl::Status RegisterLegacyKmsAeadProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
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
