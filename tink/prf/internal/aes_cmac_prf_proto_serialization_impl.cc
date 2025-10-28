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

#include "tink/prf/internal/aes_cmac_prf_proto_serialization_impl.h"

#include <array>
#include <cstdint>
#include <utility>

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
#include "tink/partial_key_access.h"
#include "tink/prf/aes_cmac_prf_key.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
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

class ProtoAesCmacPrfKeyFormat : public Message<ProtoAesCmacPrfKeyFormat> {
 public:
  ProtoAesCmacPrfKeyFormat() = default;
  using Message::SerializeAsString;

  uint32_t key_size() const { return key_size_.value(); }
  void set_key_size(uint32_t key_size) { key_size_.set_value(key_size); }

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  std::array<const OwningField*, 2> GetFields() const {
    return {&key_size_, &version_};
  }

 private:
  Uint32OwningField key_size_{1};
  Uint32OwningField version_{2};
};

class ProtoAesCmacPrfKey : public Message<ProtoAesCmacPrfKey> {
 public:
  ProtoAesCmacPrfKey() = default;

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

using AesCmacPrfProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   AesCmacPrfParameters>;
using AesCmacPrfProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<AesCmacPrfParameters,
                                       internal::ProtoParametersSerialization>;
using AesCmacPrfProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, AesCmacPrfKey>;
using AesCmacPrfProtoKeySerializerImpl =
    internal::KeySerializerImpl<AesCmacPrfKey, internal::ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCmacPrfKey";

absl::StatusOr<AesCmacPrfParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  const KeyTemplateStruct& key_template = serialization.GetKeyTemplateStruct();
  if (key_template.type_url != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesCmacPrfParameters.");
  }
  if (key_template.output_prefix_type != OutputPrefixTypeEnum::kRaw) {
    return absl::InvalidArgumentError(
        "Output prefix type must be RAW for AesCmacPrfParameters.");
  }

  ProtoAesCmacPrfKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value)) {
    return absl::InvalidArgumentError(
        "Failed to parse AesCmacPrfKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  return AesCmacPrfParameters::Create(proto_key_format.key_size());
}

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const AesCmacPrfParameters& parameters) {
  ProtoAesCmacPrfKeyFormat proto_key_format;
  proto_key_format.set_key_size(parameters.KeySizeInBytes());
  proto_key_format.set_version(0);

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixTypeEnum::kRaw,
      proto_key_format.SerializeAsString());
}

absl::StatusOr<AesCmacPrfKey> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesCmacPrfKey.");
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  if (serialization.GetOutputPrefixTypeEnum() != OutputPrefixTypeEnum::kRaw) {
    return absl::InvalidArgumentError(
        "Output prefix type must be RAW for AesCmacPrfKey.");
  }

  ProtoAesCmacPrfKey proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse AesCmacPrfKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  return AesCmacPrfKey::Create(
      RestrictedData(std::move(proto_key.key_value()), *token),
      GetPartialKeyAccess());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const AesCmacPrfKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  ProtoAesCmacPrfKey proto_key;
  proto_key.set_version(0);
  proto_key.set_key_value(restricted_input->Get(*token));

  return internal::ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(proto_key.SerializeAsSecretData(), *token),
      KeyMaterialTypeEnum::kSymmetric, OutputPrefixTypeEnum::kRaw,
      key.GetIdRequirement());
}

AesCmacPrfProtoParametersParserImpl* AesCmacPrfProtoParametersParser() {
  static auto* parser =
      new AesCmacPrfProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

AesCmacPrfProtoParametersSerializerImpl* AesCmacPrfProtoParametersSerializer() {
  static auto* serializer = new AesCmacPrfProtoParametersSerializerImpl(
      kTypeUrl, SerializeParameters);
  return serializer;
}

AesCmacPrfProtoKeyParserImpl* AesCmacPrfProtoKeyParser() {
  static auto* parser = new AesCmacPrfProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesCmacPrfProtoKeySerializerImpl* AesCmacPrfProtoKeySerializer() {
  static auto* serializer = new AesCmacPrfProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterAesCmacPrfProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(AesCmacPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      AesCmacPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(AesCmacPrfProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(AesCmacPrfProtoKeySerializer());
}

absl::Status RegisterAesCmacPrfProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(AesCmacPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterParametersSerializer(
      AesCmacPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(AesCmacPrfProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(AesCmacPrfProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
