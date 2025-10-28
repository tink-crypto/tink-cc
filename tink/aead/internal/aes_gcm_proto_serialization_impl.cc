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

#include "tink/aead/internal/aes_gcm_proto_serialization_impl.h"

#include <array>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/internal/aes_gcm_proto_format.h"
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
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::OwningField;
using ::crypto::tink::internal::proto_parsing::SecretDataOwningField;
using ::crypto::tink::internal::proto_parsing::Uint32OwningField;

class ProtoAesGcmKey : public Message<ProtoAesGcmKey> {
 public:
  ProtoAesGcmKey() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(absl::string_view value) {
    *key_value_.mutable_value() = util::SecretDataFromStringView(value);
  }

  std::array<const OwningField*, 2> GetFields() const {
    return {&version_, &key_value_};
  }

 private:
  Uint32OwningField version_{1};
  SecretDataOwningField key_value_{3};
};

using AesGcmProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, AesGcmParameters>;
using AesGcmProtoParametersSerializerImpl =
    ParametersSerializerImpl<AesGcmParameters, ProtoParametersSerialization>;
using AesGcmProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, AesGcmKey>;
using AesGcmProtoKeySerializerImpl =
    KeySerializerImpl<AesGcmKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesGcmKey";

absl::StatusOr<AesGcmParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixTypeEnum::kCrunchy:
      return AesGcmParameters::Variant::kCrunchy;
    case OutputPrefixTypeEnum::kRaw:
      return AesGcmParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return AesGcmParameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine AesGcmParameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    AesGcmParameters::Variant variant) {
  switch (variant) {
    case AesGcmParameters::Variant::kCrunchy:
      return OutputPrefixTypeEnum::kCrunchy;
    case AesGcmParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case AesGcmParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

// Legacy Tink AES-GCM key proto format assumes 12-byte random IVs and 16-byte
// tags.
absl::Status ValidateParamsForProto(const AesGcmParameters& params) {
  if (params.IvSizeInBytes() != 12) {
    return absl::InvalidArgumentError(
        "Tink currently restricts AES-GCM IV size to 12 bytes.");
  }
  if (params.TagSizeInBytes() != 16) {
    return absl::InvalidArgumentError(
        "Tink currently restricts AES-GCM tag size to 16 bytes.");
  }
  return absl::OkStatus();
}

absl::StatusOr<AesGcmParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const internal::KeyTemplateStruct& key_template =
      serialization.GetKeyTemplateStruct();
  if (key_template.type_url != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesGcmParameters.");
  }

  ProtoAesGcmKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value)) {
    return absl::InvalidArgumentError("Failed to parse AesGcmKey proto");
  }
  if (proto_key_format.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<AesGcmParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplateStruct().output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  // Legacy Tink AES-GCM key proto format assumes 12-byte random IVs and 16-byte
  // tags.
  return AesGcmParameters::Builder()
      .SetVariant(*variant)
      .SetKeySizeInBytes(proto_key_format.key_size())
      .SetIvSizeInBytes(12)
      .SetTagSizeInBytes(16)
      .Build();
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const AesGcmParameters& parameters) {
  absl::Status valid_params = ValidateParamsForProto(parameters);
  if (!valid_params.ok()) return valid_params;

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  ProtoAesGcmKeyFormat proto_key_format;
  proto_key_format.set_key_size(parameters.KeySizeInBytes());
  proto_key_format.set_version(0);
  const std::string serialized_proto = proto_key_format.SerializeAsString();
  return ProtoParametersSerialization::Create(kTypeUrl, *output_prefix_type,
                                              serialized_proto);
}

absl::StatusOr<AesGcmKey> ParseKey(const ProtoKeySerialization& serialization,
                                   absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError("Wrong type URL when parsing AesGcmKey.");
  }
  if (!token.has_value()) {
    return absl::InvalidArgumentError("SecretKeyAccess is required");
  }

  ProtoAesGcmKey proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse AesGcmKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<AesGcmParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixTypeEnum());
  if (!variant.ok()) {
    return variant.status();
  }

  // Legacy AES-GCM key proto format assumes 12-byte random IVs and 16-byte
  // tags.
  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetVariant(*variant)
          .SetKeySizeInBytes(proto_key.key_value().size())
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .Build();
  if (!parameters.ok()) return parameters.status();

  return AesGcmKey::Create(
      *parameters, RestrictedData(proto_key.key_value(), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const AesGcmKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::Status valid_params = ValidateParamsForProto(key.GetParameters());
  if (!valid_params.ok()) return valid_params;

  absl::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) return restricted_input.status();
  if (!token.has_value()) {
    return absl::InvalidArgumentError("SecretKeyAccess is required");
  }

  ProtoAesGcmKey proto_key;
  proto_key.set_version(0);
  proto_key.set_key_value(restricted_input->GetSecret(*token));

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  SecretData serialized_key = proto_key.SerializeAsSecretData();
  return ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(std::move(serialized_key), *token),
      KeyMaterialTypeEnum::kSymmetric, *output_prefix_type,
      key.GetIdRequirement());
}

AesGcmProtoParametersParserImpl* AesGcmProtoParametersParser() {
  static auto* parser =
      new AesGcmProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

AesGcmProtoParametersSerializerImpl* AesGcmProtoParametersSerializer() {
  static auto* serializer =
      new AesGcmProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

AesGcmProtoKeyParserImpl* AesGcmProtoKeyParser() {
  static auto* parser = new AesGcmProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesGcmProtoKeySerializerImpl* AesGcmProtoKeySerializer() {
  static auto* serializer = new AesGcmProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterAesGcmProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(AesGcmProtoParametersParser());
  if (!status.ok()) return status;

  status =
      registry.RegisterParametersSerializer(AesGcmProtoParametersSerializer());
  if (!status.ok()) return status;

  status = registry.RegisterKeyParser(AesGcmProtoKeyParser());
  if (!status.ok()) return status;

  return registry.RegisterKeySerializer(AesGcmProtoKeySerializer());
}

absl::Status RegisterAesGcmProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(AesGcmProtoParametersParser());
  if (!status.ok()) return status;

  status =
      builder.RegisterParametersSerializer(AesGcmProtoParametersSerializer());
  if (!status.ok()) return status;

  status = builder.RegisterKeyParser(AesGcmProtoKeyParser());
  if (!status.ok()) return status;

  return builder.RegisterKeySerializer(AesGcmProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
