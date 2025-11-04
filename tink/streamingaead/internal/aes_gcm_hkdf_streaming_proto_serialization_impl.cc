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
#include "tink/streamingaead/internal/aes_gcm_hkdf_streaming_proto_serialization_impl.h"

#include <array>
#include <cstdint>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
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
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::EnumOwningField;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageOwningField;
using ::crypto::tink::internal::proto_parsing::OwningField;
using ::crypto::tink::internal::proto_parsing::SecretDataOwningField;
using ::crypto::tink::internal::proto_parsing::Uint32OwningField;

class AesGcmHkdfStreamingParamsTP
    : public Message<AesGcmHkdfStreamingParamsTP> {
 public:
  AesGcmHkdfStreamingParamsTP() = default;
  using Message::SerializeAsString;

  uint32_t ciphertext_segment_size() const {
    return ciphertext_segment_size_.value();
  }
  void set_ciphertext_segment_size(uint32_t value) {
    ciphertext_segment_size_.set_value(value);
  }

  uint32_t derived_key_size() const { return derived_key_size_.value(); }
  void set_derived_key_size(uint32_t value) {
    derived_key_size_.set_value(value);
  }

  HashTypeEnum hkdf_hash_type() const { return hkdf_hash_type_.value(); }
  void set_hkdf_hash_type(HashTypeEnum value) {
    hkdf_hash_type_.set_value(value);
  }

  std::array<const OwningField*, 3> GetFields() const {
    return {&ciphertext_segment_size_, &derived_key_size_, &hkdf_hash_type_};
  }

 private:
  Uint32OwningField ciphertext_segment_size_{1};
  Uint32OwningField derived_key_size_{2};
  EnumOwningField<HashTypeEnum> hkdf_hash_type_{3, &HashTypeEnumIsValid};
};

class AesGcmHkdfStreamingKeyFormatTP
    : public Message<AesGcmHkdfStreamingKeyFormatTP> {
 public:
  AesGcmHkdfStreamingKeyFormatTP() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const AesGcmHkdfStreamingParamsTP& params() const { return params_.value(); }
  AesGcmHkdfStreamingParamsTP* mutable_params() {
    return params_.mutable_value();
  }

  uint32_t key_size() const { return key_size_.value(); }
  void set_key_size(uint32_t value) { key_size_.set_value(value); }

  std::array<const OwningField*, 3> GetFields() const {
    return {&params_, &key_size_, &version_};
  }

 private:
  MessageOwningField<AesGcmHkdfStreamingParamsTP> params_{1};
  Uint32OwningField key_size_{2};
  Uint32OwningField version_{3};
};

class AesGcmHkdfStreamingKeyTP : public Message<AesGcmHkdfStreamingKeyTP> {
 public:
  AesGcmHkdfStreamingKeyTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const AesGcmHkdfStreamingParamsTP& params() const { return params_.value(); }
  AesGcmHkdfStreamingParamsTP* mutable_params() {
    return params_.mutable_value();
  }

  const SecretData& key_value() const { return key_value_.value(); }
  SecretData* mutable_key_value() { return key_value_.mutable_value(); }

  std::array<const OwningField*, 3> GetFields() const {
    return {&version_, &params_, &key_value_};
  }

 private:
  Uint32OwningField version_{1};
  MessageOwningField<AesGcmHkdfStreamingParamsTP> params_{2};
  SecretDataOwningField key_value_{3};
};

using AesGcmHkdfStreamingProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization,
                         AesGcmHkdfStreamingParameters>;
using AesGcmHkdfStreamingProtoParametersSerializerImpl =
    ParametersSerializerImpl<AesGcmHkdfStreamingParameters,
                             ProtoParametersSerialization>;
using AesGcmHkdfStreamingProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, AesGcmHkdfStreamingKey>;
using AesGcmHkdfStreamingProtoKeySerializerImpl =
    KeySerializerImpl<AesGcmHkdfStreamingKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

absl::StatusOr<AesGcmHkdfStreamingParameters::HashType> FromProtoHashType(
    HashTypeEnum hash_type) {
  switch (hash_type) {
    case HashTypeEnum::kSha1:
      return AesGcmHkdfStreamingParameters::HashType::kSha1;
    case HashTypeEnum::kSha256:
      return AesGcmHkdfStreamingParameters::HashType::kSha256;
    case HashTypeEnum::kSha512:
      return AesGcmHkdfStreamingParameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("Unsupported proto hash type: ", hash_type));
  }
}

absl::StatusOr<HashTypeEnum> ToProtoHashType(
    AesGcmHkdfStreamingParameters::HashType hash_type) {
  switch (hash_type) {
    case AesGcmHkdfStreamingParameters::HashType::kSha1:
      return HashTypeEnum::kSha1;
    case AesGcmHkdfStreamingParameters::HashType::kSha256:
      return HashTypeEnum::kSha256;
    case AesGcmHkdfStreamingParameters::HashType::kSha512:
      return HashTypeEnum::kSha512;
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("Unsupported hash type: ", hash_type));
  }
}

absl::StatusOr<AesGcmHkdfStreamingParameters> ToParameters(
    const AesGcmHkdfStreamingParamsTP& params, int key_size) {
  absl::StatusOr<AesGcmHkdfStreamingParameters::HashType> hash_type =
      FromProtoHashType(params.hkdf_hash_type());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  return AesGcmHkdfStreamingParameters::Builder()
      .SetKeySizeInBytes(key_size)
      .SetDerivedKeySizeInBytes(params.derived_key_size())
      .SetHashType(*hash_type)
      .SetCiphertextSegmentSizeInBytes(params.ciphertext_segment_size())
      .Build();
}

absl::StatusOr<AesGcmHkdfStreamingParamsTP> FromParameters(
    const AesGcmHkdfStreamingParameters& parameters) {
  absl::StatusOr<HashTypeEnum> hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  AesGcmHkdfStreamingParamsTP params;
  params.set_derived_key_size(parameters.DerivedKeySizeInBytes());
  params.set_hkdf_hash_type(*hash_type);
  params.set_ciphertext_segment_size(parameters.CiphertextSegmentSizeInBytes());
  return params;
}

absl::StatusOr<AesGcmHkdfStreamingParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesGcmHkdfStreamingParameters.");
  }
  AesGcmHkdfStreamingKeyFormatTP key_format;
  if (!key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError(
        "Failed to parse AesGcmHkdfStreamingKeyFormat.");
  }

  if (key_format.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing AesGcmHkdfStreamingKeyFormat failed: only "
        "version 0 is accepted.");
  }

  return ToParameters(key_format.params(), key_format.key_size());
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const AesGcmHkdfStreamingParameters& parameters) {
  absl::StatusOr<AesGcmHkdfStreamingParamsTP> params =
      FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }
  AesGcmHkdfStreamingKeyFormatTP format;
  format.set_version(0);
  format.set_key_size(parameters.KeySizeInBytes());
  *format.mutable_params() = *params;

  return ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixTypeEnum::kRaw, format.SerializeAsString());
}

absl::StatusOr<AesGcmHkdfStreamingKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesGcmHkdfStreamingKey.");
  }

  AesGcmHkdfStreamingKeyTP key;
  if (!key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError(
        "Failed to parse AesGcmHkdfStreamingKey.");
  }

  if (key.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing AesGcmHkdfStreamingKey failed: only version 0 is accepted.");
  }

  absl::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      ToParameters(key.params(), key.key_value().size());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return AesGcmHkdfStreamingKey::Create(
      *parameters, RestrictedData(std::move(key.key_value()), *token),
      GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const AesGcmHkdfStreamingKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  absl::StatusOr<RestrictedData> initial_key_material =
      key.GetInitialKeyMaterial(GetPartialKeyAccess());
  if (!initial_key_material.ok()) {
    return initial_key_material.status();
  }

  absl::StatusOr<AesGcmHkdfStreamingParamsTP> params =
      FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }
  AesGcmHkdfStreamingKeyTP key_proto;
  key_proto.set_version(0);
  *key_proto.mutable_params() = *params;
  *key_proto.mutable_key_value() =
      util::SecretDataFromStringView(initial_key_material->GetSecret(*token));

  return ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(key_proto.SerializeAsSecretData(), *token),
      KeyMaterialTypeEnum::kSymmetric, OutputPrefixTypeEnum::kRaw,
      key.GetIdRequirement());
}

AesGcmHkdfStreamingProtoParametersParserImpl*
AesGcmHkdfStreamingProtoParametersParser() {
  static auto* parser = new AesGcmHkdfStreamingProtoParametersParserImpl(
      kTypeUrl, ParseParameters);
  return parser;
}

AesGcmHkdfStreamingProtoParametersSerializerImpl*
AesGcmHkdfStreamingProtoParametersSerializer() {
  static auto* serializer =
      new AesGcmHkdfStreamingProtoParametersSerializerImpl(kTypeUrl,
                                                           SerializeParameters);
  return serializer;
}

AesGcmHkdfStreamingProtoKeyParserImpl* AesGcmHkdfStreamingProtoKeyParser() {
  static auto* parser =
      new AesGcmHkdfStreamingProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesGcmHkdfStreamingProtoKeySerializerImpl*
AesGcmHkdfStreamingProtoKeySerializer() {
  static auto* serializer =
      new AesGcmHkdfStreamingProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterAesGcmHkdfStreamingProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status = registry.RegisterParametersParser(
      AesGcmHkdfStreamingProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      AesGcmHkdfStreamingProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(AesGcmHkdfStreamingProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(
      AesGcmHkdfStreamingProtoKeySerializer());
}

absl::Status RegisterAesGcmHkdfStreamingProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status = builder.RegisterParametersParser(
      AesGcmHkdfStreamingProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterParametersSerializer(
      AesGcmHkdfStreamingProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(AesGcmHkdfStreamingProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(AesGcmHkdfStreamingProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
