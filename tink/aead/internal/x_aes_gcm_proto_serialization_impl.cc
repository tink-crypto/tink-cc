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

#include "tink/aead/internal/x_aes_gcm_proto_serialization_impl.h"

#include <array>
#include <cstdint>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/aead/x_aes_gcm_parameters.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_secret_data_field.h"
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

using ::crypto::tink::internal::proto_parsing::Field;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageField;
using ::crypto::tink::internal::proto_parsing::Uint32Field;

class XAesGcmParamsTP : public Message<XAesGcmParamsTP> {
 public:
  XAesGcmParamsTP() = default;

  uint32_t salt_size() const { return salt_size_.value(); }
  void set_salt_size(uint32_t value) { salt_size_.set_value(value); }

  std::array<const Field*, 1> GetFields() const { return {&salt_size_}; }

 private:
  Uint32Field salt_size_{1};
};

class XAesGcmKeyFormatTP : public Message<XAesGcmKeyFormatTP> {
 public:
  XAesGcmKeyFormatTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const XAesGcmParamsTP& params() const { return params_.value(); }
  XAesGcmParamsTP* mutable_params() { return params_.mutable_value(); }

  std::array<const Field*, 2> GetFields() const {
    return {&version_, &params_};
  }

  // This is OK because this class doesn't contain secret data.
  using Message::SerializeAsString;

 private:
  Uint32Field version_{1};
  // reserved : 2
  MessageField<XAesGcmParamsTP> params_{3};
};

class XAesGcmKeyTP : public Message<XAesGcmKeyTP> {
 public:
  XAesGcmKeyTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const XAesGcmParamsTP& params() const { return params_.value(); }
  XAesGcmParamsTP* mutable_params() { return params_.mutable_value(); }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(absl::string_view value) {
    *key_value_.mutable_value() = util::SecretDataFromStringView(value);
  }

  std::array<const Field*, 3> GetFields() const {
    return {&version_, &params_, &key_value_};
  }

 private:
  Uint32Field version_{1};
  MessageField<XAesGcmParamsTP> params_{2};
  proto_parsing::SecretDataField key_value_{3};
};

using XAesGcmProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, XAesGcmParameters>;
using XAesGcmProtoParametersSerializerImpl =
    ParametersSerializerImpl<XAesGcmParameters, ProtoParametersSerialization>;
using XAesGcmProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, XAesGcmKey>;
using XAesGcmProtoKeySerializerImpl =
    KeySerializerImpl<XAesGcmKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.XAesGcmKey";

absl::StatusOr<XAesGcmParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kRaw:
      return XAesGcmParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return XAesGcmParameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine XAesGcmParameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    XAesGcmParameters::Variant variant) {
  switch (variant) {
    case XAesGcmParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case XAesGcmParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

absl::StatusOr<XAesGcmParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const internal::KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing XAesGcmParameters.");
  }

  XAesGcmKeyFormatTP proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError("Failed to parse XAesGcmKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<XAesGcmParameters::Variant> variant =
      ToVariant(key_template.output_prefix_type());
  if (!variant.ok()) {
    return variant.status();
  }

  return XAesGcmParameters::Create(*variant,
                                   proto_key_format.params().salt_size());
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const XAesGcmParameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  XAesGcmKeyFormatTP proto_key_format;
  proto_key_format.set_version(0);
  proto_key_format.mutable_params()->set_salt_size(parameters.SaltSizeBytes());

  return ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

absl::StatusOr<XAesGcmKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing XAesGcmKey.");
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  XAesGcmKeyTP proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse XAesGcmKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<XAesGcmParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixTypeEnum());
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<XAesGcmParameters> parameters =
      XAesGcmParameters::Create(*variant, proto_key.params().salt_size());
  if (!parameters.ok()) {
    return parameters.status();
  }
  return XAesGcmKey::Create(
      *parameters, RestrictedData(proto_key.key_value(), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const XAesGcmKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  XAesGcmKeyTP proto_key;
  proto_key.set_version(0);
  proto_key.mutable_params()->set_salt_size(
      key.GetParameters().SaltSizeBytes());
  proto_key.set_key_value(restricted_input->GetSecret(*token));
  SecretData serialized_key = proto_key.SerializeAsSecretData();
  RestrictedData restricted_output =
      RestrictedData(std::move(serialized_key), *token);

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, KeyMaterialTypeEnum::kSymmetric,
      *output_prefix_type, key.GetIdRequirement());
}

XAesGcmProtoParametersParserImpl* XAesGcmProtoParametersParser() {
  static auto* parser =
      new XAesGcmProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

XAesGcmProtoParametersSerializerImpl* XAesGcmProtoParametersSerializer() {
  static auto* serializer =
      new XAesGcmProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

XAesGcmProtoKeyParserImpl* XAesGcmProtoKeyParser() {
  static auto* parser = new XAesGcmProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

XAesGcmProtoKeySerializerImpl* XAesGcmProtoKeySerializer() {
  static auto* serializer = new XAesGcmProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterXAesGcmProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(XAesGcmProtoParametersParser());
  if (!status.ok()) {
    return status;
  }
  status =
      registry.RegisterParametersSerializer(XAesGcmProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }
  status = registry.RegisterKeyParser(XAesGcmProtoKeyParser());
  if (!status.ok()) {
    return status;
  }
  return registry.RegisterKeySerializer(XAesGcmProtoKeySerializer());
}

absl::Status RegisterXAesGcmProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(XAesGcmProtoParametersParser());
  if (!status.ok()) {
    return status;
  }
  status =
      builder.RegisterParametersSerializer(XAesGcmProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }
  status = builder.RegisterKeyParser(XAesGcmProtoKeyParser());
  if (!status.ok()) {
    return status;
  }
  return builder.RegisterKeySerializer(XAesGcmProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
