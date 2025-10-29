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

#include "tink/aead/internal/aes_eax_proto_serialization_impl.h"

#include <array>
#include <cstdint>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_eax_key.h"
#include "tink/aead/aes_eax_parameters.h"
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
using ::crypto::tink::internal::proto_parsing::MessageOwningField;
using ::crypto::tink::internal::proto_parsing::OwningBytesField;
using ::crypto::tink::internal::proto_parsing::OwningField;
using ::crypto::tink::internal::proto_parsing::SecretDataOwningField;
using ::crypto::tink::internal::proto_parsing::Uint32OwningField;

using AesEaxProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, AesEaxParameters>;
using AesEaxProtoParametersSerializerImpl =
    ParametersSerializerImpl<AesEaxParameters, ProtoParametersSerialization>;
using AesEaxProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, AesEaxKey>;
using AesEaxProtoKeySerializerImpl =
    KeySerializerImpl<AesEaxKey, ProtoKeySerialization>;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesEaxKey";

class ProtoAesEaxParams : public Message<ProtoAesEaxParams> {
 public:
  ProtoAesEaxParams() = default;

  uint32_t iv_size() const { return iv_size_.value(); }
  void set_iv_size(uint32_t value) { iv_size_.set_value(value); }

  std::array<const OwningField*, 1> GetFields() const { return {&iv_size_}; }

 private:
  Uint32OwningField iv_size_{1};
};

class ProtoAesEaxKeyFormat : public Message<ProtoAesEaxKeyFormat> {
 public:
  ProtoAesEaxKeyFormat() = default;

  const ProtoAesEaxParams& params() const { return params_.value(); }
  ProtoAesEaxParams* mutable_params() { return params_.mutable_value(); }

  uint32_t key_size() const { return key_size_.value(); }
  void set_key_size(uint32_t value) { key_size_.set_value(value); }

  std::array<const OwningField*, 2> GetFields() const {
    return {&params_, &key_size_};
  }

  // This is OK because this class doesn't contain secret data.
  using Message::SerializeAsString;

 private:
  MessageOwningField<ProtoAesEaxParams> params_{1};
  Uint32OwningField key_size_{2};
};

class ProtoAesEaxKey : public Message<ProtoAesEaxKey> {
 public:
  ProtoAesEaxKey() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const ProtoAesEaxParams& params() const { return params_.value(); }
  ProtoAesEaxParams* mutable_params() { return params_.mutable_value(); }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(absl::string_view value) {
    *key_value_.mutable_value() = util::SecretDataFromStringView(value);
  }

  std::array<const OwningField*, 3> GetFields() const {
    return {&version_, &params_, &key_value_};
  }

 private:
  Uint32OwningField version_{1};
  MessageOwningField<ProtoAesEaxParams> params_{2};
  SecretDataOwningField key_value_{3};
};

absl::StatusOr<AesEaxParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixTypeEnum::kCrunchy:
      return AesEaxParameters::Variant::kCrunchy;
    case OutputPrefixTypeEnum::kRaw:
      return AesEaxParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return AesEaxParameters::Variant::kTink;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine AesEaxParameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    AesEaxParameters::Variant variant) {
  switch (variant) {
    case AesEaxParameters::Variant::kCrunchy:
      return OutputPrefixTypeEnum::kCrunchy;
    case AesEaxParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case AesEaxParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

absl::StatusOr<ProtoAesEaxParams> GetProtoParams(
    const AesEaxParameters& parameters) {
  // Legacy Tink AES-EAX key proto format assumes 16-byte tags.
  if (parameters.GetTagSizeInBytes() != 16) {
    return absl::InvalidArgumentError(
        "Tink currently restricts AES-EAX tag size to 16 bytes.");
  }

  ProtoAesEaxParams params;
  params.set_iv_size(parameters.GetIvSizeInBytes());
  return params;
}

absl::StatusOr<AesEaxParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const internal::ProtoKeyTemplate& key_template =
      serialization.GetProtoKeyTemplate();
  if (key_template.type_url() != kTypeUrl) {
    return absl::InvalidArgumentError(
        absl::StrCat("Wrong type URL when parsing AesEaxParameters: ",
                     key_template.type_url()));
  }

  ProtoAesEaxKeyFormat key_format;
  if (!key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError("Failed to parse AesEaxKeyFormat proto");
  }

  absl::StatusOr<AesEaxParameters::Variant> variant =
      ToVariant(key_template.output_prefix_type());
  if (!variant.ok()) {
    return variant.status();
  }

  // Legacy Tink AES-EAX key proto format assumes 16-byte tags only.
  return AesEaxParameters::Builder()
      .SetVariant(*variant)
      .SetKeySizeInBytes(key_format.key_size())
      .SetIvSizeInBytes(key_format.params().iv_size())
      .SetTagSizeInBytes(16)
      .Build();
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const AesEaxParameters& parameters) {
  absl::StatusOr<ProtoAesEaxParams> params = GetProtoParams(parameters);
  if (!params.ok()) {
    return params.status();
  }

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  ProtoAesEaxKeyFormat key_format;
  key_format.mutable_params()->set_iv_size(params->iv_size());
  key_format.set_key_size(parameters.GetKeySizeInBytes());

  return ProtoParametersSerialization::Create(kTypeUrl, *output_prefix_type,
                                              key_format.SerializeAsString());
}

absl::StatusOr<AesEaxKey> ParseKey(const ProtoKeySerialization& serialization,
                                   absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesEaxKey.");
  }
  if (!token.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }

  ProtoAesEaxKey key;
  if (!key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse AesEaxKey proto");
  }
  if (key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<AesEaxParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixTypeEnum());
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetVariant(*variant)
          .SetKeySizeInBytes(key.key_value().size())
          .SetIvSizeInBytes(key.params().iv_size())
          // Legacy AES-EAX key proto format assumes 16-byte tags.
          .SetTagSizeInBytes(16)
          .Build();
  if (!parameters.ok()) return parameters.status();

  return AesEaxKey::Create(*parameters, RestrictedData(key.key_value(), *token),
                           serialization.IdRequirement(),
                           GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const AesEaxKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<ProtoAesEaxParams> params =
      GetProtoParams(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  absl::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) return restricted_input.status();
  if (!token.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "SecretKeyAccess is required");
  }

  ProtoAesEaxKey proto_key;
  proto_key.set_version(0);
  proto_key.mutable_params()->set_iv_size(params->iv_size());
  proto_key.set_key_value(restricted_input->GetSecret(*token));

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  SecretData serialized_proto = proto_key.SerializeAsSecretData();
  return ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(std::move(serialized_proto), *token),
      KeyMaterialTypeEnum::kSymmetric, *output_prefix_type,
      key.GetIdRequirement());
}

AesEaxProtoParametersParserImpl* AesEaxProtoParametersParser() {
  static auto* parser =
      new AesEaxProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

AesEaxProtoParametersSerializerImpl* AesEaxProtoParametersSerializer() {
  static auto* serializer =
      new AesEaxProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

AesEaxProtoKeyParserImpl* AesEaxProtoKeyParser() {
  static auto* parser = new AesEaxProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesEaxProtoKeySerializerImpl* AesEaxProtoKeySerializer() {
  static auto* serializer = new AesEaxProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterAesEaxProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(AesEaxProtoParametersParser());
  if (!status.ok()) return status;

  status =
      registry.RegisterParametersSerializer(AesEaxProtoParametersSerializer());
  if (!status.ok()) return status;

  status = registry.RegisterKeyParser(AesEaxProtoKeyParser());
  if (!status.ok()) return status;

  return registry.RegisterKeySerializer(AesEaxProtoKeySerializer());
}

absl::Status RegisterAesEaxProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(AesEaxProtoParametersParser());
  if (!status.ok()) return status;

  status =
      builder.RegisterParametersSerializer(AesEaxProtoParametersSerializer());
  if (!status.ok()) return status;

  status = builder.RegisterKeyParser(AesEaxProtoKeyParser());
  if (!status.ok()) return status;

  return builder.RegisterKeySerializer(AesEaxProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
