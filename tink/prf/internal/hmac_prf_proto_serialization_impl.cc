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

#include "tink/prf/internal/hmac_prf_proto_serialization_impl.h"

#include <array>
#include <cstdint>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/common_proto_enums.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/proto_parser_enum_field.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_secret_data_field.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/prf/hmac_prf_key.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::EnumField;
using ::crypto::tink::internal::proto_parsing::Field;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageField;
using ::crypto::tink::internal::proto_parsing::SecretDataField;
using ::crypto::tink::internal::proto_parsing::Uint32Field;

class HmacPrfParamsTP : public Message {
 public:
  HmacPrfParamsTP() = default;
  using Message::SerializeAsString;

  HashTypeEnum hash() const { return hash_.value(); }
  void set_hash(HashTypeEnum hash) { hash_.set_value(hash); }

 private:
  size_t num_fields() const override { return 1; }
  const Field* field(int i) const override {
    return std::array<const Field*, 1>{&hash_}[i];
  }
  EnumField<HashTypeEnum> hash_{1, &HashTypeEnumIsValid};
};

class HmacPrfKeyTP : public Message {
 public:
  HmacPrfKeyTP() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const HmacPrfParamsTP& params() const { return params_.value(); }
  HmacPrfParamsTP* mutable_params() { return params_.mutable_value(); }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(SecretData key_value) {
    *key_value_.mutable_value() = std::move(key_value);
  }

 private:
  size_t num_fields() const override { return 3; }
  const Field* field(int i) const override {
    return std::array<const Field*, 3>{&version_, &params_, &key_value_}[i];
  }
  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  MessageField<HmacPrfParamsTP> params_{2};
  SecretDataField key_value_{3};
};

class HmacPrfKeyFormatTP : public Message {
 public:
  HmacPrfKeyFormatTP() = default;
  using Message::SerializeAsString;

  const HmacPrfParamsTP& params() const { return params_.value(); }
  HmacPrfParamsTP* mutable_params() { return params_.mutable_value(); }

  uint32_t key_size() const { return key_size_.value(); }
  void set_key_size(uint32_t key_size) { key_size_.set_value(key_size); }

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

 private:
  size_t num_fields() const override { return 3; }
  const Field* field(int i) const override {
    return std::array<const Field*, 3>{&params_, &key_size_, &version_}[i];
  }
  MessageField<HmacPrfParamsTP> params_{1};
  Uint32Field key_size_{2, ProtoFieldOptions::kImplicit};
  Uint32Field version_{3, ProtoFieldOptions::kImplicit};
};

using HmacPrfProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, HmacPrfParameters>;
using HmacPrfProtoParametersSerializerImpl =
    ParametersSerializerImpl<HmacPrfParameters, ProtoParametersSerialization>;
using HmacPrfProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, HmacPrfKey>;
using HmacPrfProtoKeySerializerImpl =
    KeySerializerImpl<HmacPrfKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.HmacPrfKey";

absl::StatusOr<HmacPrfParameters::HashType> ToHashType(HashTypeEnum hash_type) {
  switch (hash_type) {
    case HashTypeEnum::kSha1:
      return HmacPrfParameters::HashType::kSha1;
    case HashTypeEnum::kSha224:
      return HmacPrfParameters::HashType::kSha224;
    case HashTypeEnum::kSha256:
      return HmacPrfParameters::HashType::kSha256;
    case HashTypeEnum::kSha384:
      return HmacPrfParameters::HashType::kSha384;
    case HashTypeEnum::kSha512:
      return HmacPrfParameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError("Could not determine HashType");
  }
}

absl::StatusOr<HashTypeEnum> ToProtoHashType(
    HmacPrfParameters::HashType hash_type) {
  switch (hash_type) {
    case HmacPrfParameters::HashType::kSha1:
      return HashTypeEnum::kSha1;
    case HmacPrfParameters::HashType::kSha224:
      return HashTypeEnum::kSha224;
    case HmacPrfParameters::HashType::kSha256:
      return HashTypeEnum::kSha256;
    case HmacPrfParameters::HashType::kSha384:
      return HashTypeEnum::kSha384;
    case HmacPrfParameters::HashType::kSha512:
      return HashTypeEnum::kSha512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine HmacPrfParameters::HashType");
  }
}

absl::StatusOr<HmacPrfParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing HmacPrfParameters.");
  }
  if (key_template.output_prefix_type() != OutputPrefixTypeEnum::kRaw) {
    return absl::InvalidArgumentError(
        "Output prefix type must be RAW for HmacPrfParameters.");
  }

  HmacPrfKeyFormatTP proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError("Failed to parse HmacPrfKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<HmacPrfParameters::HashType> hash_type =
      ToHashType(proto_key_format.params().hash());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  return HmacPrfParameters::Create(proto_key_format.key_size(), *hash_type);
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const HmacPrfParameters& parameters) {
  absl::StatusOr<HashTypeEnum> proto_hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!proto_hash_type.ok()) {
    return proto_hash_type.status();
  }

  HmacPrfKeyFormatTP proto_key_format;
  proto_key_format.mutable_params()->set_hash(*proto_hash_type);
  proto_key_format.set_key_size(parameters.KeySizeInBytes());
  proto_key_format.set_version(0);

  return ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixTypeEnum::kRaw,
      proto_key_format.SerializeAsString());
}

absl::StatusOr<HmacPrfKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing HmacPrfKey.");
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  if (serialization.GetOutputPrefixTypeEnum() != OutputPrefixTypeEnum::kRaw) {
    return absl::InvalidArgumentError(
        "Output prefix type must be RAW for HmacPrfKey.");
  }

  HmacPrfKeyTP proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse HmacPrfKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<HmacPrfParameters::HashType> hash_type =
      ToHashType(proto_key.params().hash());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  absl::StatusOr<HmacPrfParameters> parameters =
      HmacPrfParameters::Create(proto_key.key_value().size(), *hash_type);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return HmacPrfKey::Create(
      *parameters, RestrictedData(std::move(proto_key.key_value()), *token),
      GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const HmacPrfKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  absl::StatusOr<HashTypeEnum> proto_hash_type =
      ToProtoHashType(key.GetParameters().GetHashType());
  if (!proto_hash_type.ok()) {
    return proto_hash_type.status();
  }

  HmacPrfKeyTP proto_key;
  proto_key.set_version(0);
  proto_key.mutable_params()->set_hash(*proto_hash_type);
  proto_key.set_key_value(restricted_input->Get(*token));

  return ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(proto_key.SerializeAsSecretData(), *token),
      KeyMaterialTypeEnum::kSymmetric, OutputPrefixTypeEnum::kRaw,
      key.GetIdRequirement());
}

HmacPrfProtoParametersParserImpl* HmacPrfProtoParametersParser() {
  static auto* parser =
      new HmacPrfProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

HmacPrfProtoParametersSerializerImpl* HmacPrfProtoParametersSerializer() {
  static auto* serializer =
      new HmacPrfProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

HmacPrfProtoKeyParserImpl* HmacPrfProtoKeyParser() {
  static auto* parser = new HmacPrfProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

HmacPrfProtoKeySerializerImpl* HmacPrfProtoKeySerializer() {
  static auto* serializer = new HmacPrfProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterHmacPrfProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(HmacPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      registry.RegisterParametersSerializer(HmacPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(HmacPrfProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(HmacPrfProtoKeySerializer());
}

absl::Status RegisterHmacPrfProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(HmacPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      builder.RegisterParametersSerializer(HmacPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(HmacPrfProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(HmacPrfProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
