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

#include "tink/prf/internal/hkdf_prf_proto_serialization_impl.h"

#include <array>
#include <cstdint>
#include <string>
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
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/internal/proto_parser_secret_data_owning_field.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::EnumOwningField;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageOwningField;
using ::crypto::tink::internal::proto_parsing::OwningBytesField;
using ::crypto::tink::internal::proto_parsing::OwningField;
using ::crypto::tink::internal::proto_parsing::SecretDataOwningField;
using ::crypto::tink::internal::proto_parsing::Uint32OwningField;

class HkdfPrfParamsTP : public Message<HkdfPrfParamsTP> {
 public:
  HkdfPrfParamsTP() = default;
  using Message::SerializeAsString;

  HashTypeEnum hash() const { return hash_.value(); }
  void set_hash(HashTypeEnum hash) { hash_.set_value(hash); }

  const std::string& salt() const { return salt_.value(); }
  void set_salt(absl::string_view salt) { salt_.set_value(salt); }

  std::array<const OwningField*, 2> GetFields() const {
    return {&hash_, &salt_};
  }

 private:
  EnumOwningField<HashTypeEnum> hash_{1, &HashTypeEnumIsValid};
  OwningBytesField<std::string> salt_{2};
};

class HkdfPrfKeyTP : public Message<HkdfPrfKeyTP> {
 public:
  HkdfPrfKeyTP() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const HkdfPrfParamsTP& params() const { return params_.value(); }
  HkdfPrfParamsTP* mutable_params() { return params_.mutable_value(); }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(SecretData key_value) {
    *key_value_.mutable_value() = std::move(key_value);
  }

  std::array<const OwningField*, 3> GetFields() const {
    return {&version_, &params_, &key_value_};
  }

 private:
  Uint32OwningField version_{1};
  MessageOwningField<HkdfPrfParamsTP> params_{2};
  SecretDataOwningField key_value_{3};
};

class HkdfPrfKeyFormatTP : public Message<HkdfPrfKeyFormatTP> {
 public:
  HkdfPrfKeyFormatTP() = default;
  using Message::SerializeAsString;

  const HkdfPrfParamsTP& params() const { return params_.value(); }
  HkdfPrfParamsTP* mutable_params() { return params_.mutable_value(); }

  uint32_t key_size() const { return key_size_.value(); }
  void set_key_size(uint32_t key_size) { key_size_.set_value(key_size); }

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  std::array<const OwningField*, 3> GetFields() const {
    return {&params_, &key_size_, &version_};
  }

 private:
  MessageOwningField<HkdfPrfParamsTP> params_{1};
  Uint32OwningField key_size_{2};
  Uint32OwningField version_{3};
};

using HkdfPrfProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, HkdfPrfParameters>;
using HkdfPrfProtoParametersSerializerImpl =
    ParametersSerializerImpl<HkdfPrfParameters, ProtoParametersSerialization>;
using HkdfPrfProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, HkdfPrfKey>;
using HkdfPrfProtoKeySerializerImpl =
    KeySerializerImpl<HkdfPrfKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.HkdfPrfKey";

absl::StatusOr<HkdfPrfParameters::HashType> ToHashType(HashTypeEnum hash_type) {
  switch (hash_type) {
    case HashTypeEnum::kSha1:
      return HkdfPrfParameters::HashType::kSha1;
    case HashTypeEnum::kSha224:
      return HkdfPrfParameters::HashType::kSha224;
    case HashTypeEnum::kSha256:
      return HkdfPrfParameters::HashType::kSha256;
    case HashTypeEnum::kSha384:
      return HkdfPrfParameters::HashType::kSha384;
    case HashTypeEnum::kSha512:
      return HkdfPrfParameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError("Could not determine HashType");
  }
}

absl::StatusOr<HashTypeEnum> ToProtoHashType(
    HkdfPrfParameters::HashType hash_type) {
  switch (hash_type) {
    case HkdfPrfParameters::HashType::kSha1:
      return HashTypeEnum::kSha1;
    case HkdfPrfParameters::HashType::kSha224:
      return HashTypeEnum::kSha224;
    case HkdfPrfParameters::HashType::kSha256:
      return HashTypeEnum::kSha256;
    case HkdfPrfParameters::HashType::kSha384:
      return HashTypeEnum::kSha384;
    case HkdfPrfParameters::HashType::kSha512:
      return HashTypeEnum::kSha512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine HkdfPrfParameters::HashType");
  }
}

absl::StatusOr<HkdfPrfParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing HkdfPrfParameters.");
  }
  if (serialization.GetKeyTemplate().output_prefix_type() !=
      OutputPrefixTypeEnum::kRaw) {
    return absl::InvalidArgumentError(
        "Output prefix type must be RAW for HkdfPrfParameters.");
  }

  HkdfPrfKeyFormatTP proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse HkdfPrfKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  absl::StatusOr<HkdfPrfParameters::HashType> hash_type =
      ToHashType(proto_key_format.params().hash());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  if (!proto_key_format.params().salt().empty()) {
    return HkdfPrfParameters::Create(proto_key_format.key_size(), *hash_type,
                                     proto_key_format.params().salt());
  }

  return HkdfPrfParameters::Create(proto_key_format.key_size(), *hash_type,
                                   absl::nullopt);
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const HkdfPrfParameters& parameters) {
  absl::StatusOr<HashTypeEnum> proto_hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!proto_hash_type.ok()) {
    return proto_hash_type.status();
  }

  HkdfPrfKeyFormatTP proto_key_format;
  proto_key_format.set_version(0);
  proto_key_format.set_key_size(parameters.KeySizeInBytes());
  proto_key_format.mutable_params()->set_hash(*proto_hash_type);
  if (parameters.GetSalt().has_value()) {
    proto_key_format.mutable_params()->set_salt(*parameters.GetSalt());
  }

  return ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixTypeEnum::kRaw,
      proto_key_format.SerializeAsString());
}

absl::StatusOr<HkdfPrfKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing HkdfPrfKey.");
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  if (serialization.GetOutputPrefixTypeEnum() != OutputPrefixTypeEnum::kRaw) {
    return absl::InvalidArgumentError(
        "Output prefix type must be RAW for HkdfPrfKey.");
  }

  HkdfPrfKeyTP proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse HkdfPrfKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  absl::StatusOr<HkdfPrfParameters::HashType> hash_type =
      ToHashType(proto_key.params().hash());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  absl::optional<std::string> salt = absl::nullopt;
  if (!proto_key.params().salt().empty()) {
    salt = proto_key.params().salt();
  }

  absl::StatusOr<HkdfPrfParameters> parameters =
      HkdfPrfParameters::Create(proto_key.key_value().size(), *hash_type, salt);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return HkdfPrfKey::Create(
      *parameters, RestrictedData(std::move(proto_key.key_value()), *token),
      GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const HkdfPrfKey& key, absl::optional<SecretKeyAccessToken> token) {
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

  HkdfPrfKeyTP proto_key;
  proto_key.set_version(0);
  proto_key.mutable_params()->set_hash(*proto_hash_type);
  if (key.GetParameters().GetSalt().has_value()) {
    proto_key.mutable_params()->set_salt(*key.GetParameters().GetSalt());
  }
  proto_key.set_key_value(restricted_input->Get(*token));

  return ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(proto_key.SerializeAsSecretData(), *token),
      KeyMaterialTypeEnum::kSymmetric, OutputPrefixTypeEnum::kRaw,
      key.GetIdRequirement());
}

HkdfPrfProtoParametersParserImpl& HkdfPrfProtoParametersParser() {
  static auto* parser =
      new HkdfPrfProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return *parser;
}

HkdfPrfProtoParametersSerializerImpl& HkdfPrfProtoParametersSerializer() {
  static auto* serializer =
      new HkdfPrfProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return *serializer;
}

HkdfPrfProtoKeyParserImpl& HkdfPrfProtoKeyParser() {
  static auto* parser = new HkdfPrfProtoKeyParserImpl(kTypeUrl, ParseKey);
  return *parser;
}

HkdfPrfProtoKeySerializerImpl& HkdfPrfProtoKeySerializer() {
  static auto* serializer = new HkdfPrfProtoKeySerializerImpl(SerializeKey);
  return *serializer;
}

}  // namespace

absl::Status RegisterHkdfPrfProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(&HkdfPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      &HkdfPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(&HkdfPrfProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(&HkdfPrfProtoKeySerializer());
}

absl::Status RegisterHkdfPrfProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(&HkdfPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      builder.RegisterParametersSerializer(&HkdfPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(&HkdfPrfProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(&HkdfPrfProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
