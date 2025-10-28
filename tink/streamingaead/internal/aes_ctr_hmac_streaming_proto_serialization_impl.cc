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

#include "tink/streamingaead/internal/aes_ctr_hmac_streaming_proto_serialization_impl.h"

#include <sys/types.h>

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
#include "tink/streamingaead/aes_ctr_hmac_streaming_key.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"

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

class ProtoHmacParams : public Message<ProtoHmacParams> {
 public:
  ProtoHmacParams() = default;
  using Message::SerializeAsString;

  HashTypeEnum hash() const { return hash_.value(); }
  void set_hash(HashTypeEnum hash) { hash_.set_value(hash); }

  uint32_t tag_size() const { return tag_size_.value(); }
  void set_tag_size(uint32_t tag_size) { tag_size_.set_value(tag_size); }

  std::array<const OwningField*, 2> GetFields() const {
    return {&hash_, &tag_size_};
  }

 private:
  EnumOwningField<HashTypeEnum> hash_{1, &HashTypeEnumIsValid};
  Uint32OwningField tag_size_{2};
};

class ProtoAesCtrHmacStreamingParams
    : public Message<ProtoAesCtrHmacStreamingParams> {
 public:
  ProtoAesCtrHmacStreamingParams() = default;
  using Message::SerializeAsString;

  uint32_t ciphertext_segment_size() const {
    return ciphertext_segment_size_.value();
  }
  void set_ciphertext_segment_size(uint32_t size) {
    ciphertext_segment_size_.set_value(size);
  }

  uint32_t derived_key_size() const { return derived_key_size_.value(); }
  void set_derived_key_size(uint32_t size) {
    derived_key_size_.set_value(size);
  }

  HashTypeEnum hkdf_hash_type() const { return hkdf_hash_type_.value(); }
  void set_hkdf_hash_type(HashTypeEnum hash_type) {
    hkdf_hash_type_.set_value(hash_type);
  }

  const ProtoHmacParams& hmac_params() const { return hmac_params_.value(); }
  ProtoHmacParams* mutable_hmac_params() {
    return hmac_params_.mutable_value();
  }

  std::array<const OwningField*, 4> GetFields() const {
    return {&ciphertext_segment_size_, &derived_key_size_, &hkdf_hash_type_,
            &hmac_params_};
  }

 private:
  Uint32OwningField ciphertext_segment_size_{1};
  Uint32OwningField derived_key_size_{2};
  EnumOwningField<HashTypeEnum> hkdf_hash_type_{3, &HashTypeEnumIsValid};
  MessageOwningField<ProtoHmacParams> hmac_params_{4};
};

class ProtoAesCtrHmacStreamingKeyFormat
    : public Message<ProtoAesCtrHmacStreamingKeyFormat> {
 public:
  ProtoAesCtrHmacStreamingKeyFormat() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const ProtoAesCtrHmacStreamingParams& params() const {
    return params_.value();
  }
  ProtoAesCtrHmacStreamingParams* mutable_params() {
    return params_.mutable_value();
  }

  uint32_t key_size() const { return key_size_.value(); }
  void set_key_size(uint32_t key_size) { key_size_.set_value(key_size); }

  std::array<const OwningField*, 3> GetFields() const {
    return {&params_, &key_size_, &version_};
  }

 private:
  MessageOwningField<ProtoAesCtrHmacStreamingParams> params_{1};
  Uint32OwningField key_size_{2};
  Uint32OwningField version_{3};
};

class ProtoAesCtrHmacStreamingKey
    : public Message<ProtoAesCtrHmacStreamingKey> {
 public:
  ProtoAesCtrHmacStreamingKey() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const ProtoAesCtrHmacStreamingParams& params() const {
    return params_.value();
  }
  ProtoAesCtrHmacStreamingParams* mutable_params() {
    return params_.mutable_value();
  }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(SecretData key_value) {
    *key_value_.mutable_value() = std::move(key_value);
  }

  std::array<const OwningField*, 3> GetFields() const {
    return {&version_, &params_, &key_value_};
  }

 private:
  Uint32OwningField version_{1};
  MessageOwningField<ProtoAesCtrHmacStreamingParams> params_{2};
  SecretDataOwningField key_value_{3};
};

using AesCtrHmacStreamingProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization,
                         AesCtrHmacStreamingParameters>;
using AesCtrHmacStreamingProtoParametersSerializerImpl =
    ParametersSerializerImpl<AesCtrHmacStreamingParameters,
                             ProtoParametersSerialization>;
using AesCtrHmacStreamingProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, AesCtrHmacStreamingKey>;
using AesCtrHmacStreamingProtoKeySerializerImpl =
    KeySerializerImpl<AesCtrHmacStreamingKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";

absl::StatusOr<AesCtrHmacStreamingParameters::HashType> FromProtoHashType(
    HashTypeEnum hash_type) {
  switch (hash_type) {
    case HashTypeEnum::kSha1:
      return AesCtrHmacStreamingParameters::HashType::kSha1;
    case HashTypeEnum::kSha256:
      return AesCtrHmacStreamingParameters::HashType::kSha256;
    case HashTypeEnum::kSha512:
      return AesCtrHmacStreamingParameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError("Unsupported proto hash type");
  }
}

absl::StatusOr<HashTypeEnum> ToProtoHashType(
    AesCtrHmacStreamingParameters::HashType hash_type) {
  switch (hash_type) {
    case AesCtrHmacStreamingParameters::HashType::kSha1:
      return HashTypeEnum::kSha1;
    case AesCtrHmacStreamingParameters::HashType::kSha256:
      return HashTypeEnum::kSha256;
    case AesCtrHmacStreamingParameters::HashType::kSha512:
      return HashTypeEnum::kSha512;
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("Unsupported hash type: ", hash_type));
  }
}

absl::StatusOr<AesCtrHmacStreamingParameters> ToParameters(
    const ProtoAesCtrHmacStreamingParams& params_proto, int key_size) {
  absl::StatusOr<AesCtrHmacStreamingParameters::HashType> hkdf_hash_type =
      FromProtoHashType(params_proto.hkdf_hash_type());
  if (!hkdf_hash_type.ok()) {
    return hkdf_hash_type.status();
  }
  absl::StatusOr<AesCtrHmacStreamingParameters::HashType> hmac_hash_type =
      FromProtoHashType(params_proto.hmac_params().hash());
  if (!hmac_hash_type.ok()) {
    return hmac_hash_type.status();
  }

  return AesCtrHmacStreamingParameters::Builder()
      .SetKeySizeInBytes(key_size)
      .SetDerivedKeySizeInBytes(params_proto.derived_key_size())
      .SetHkdfHashType(*hkdf_hash_type)
      .SetHmacHashType(*hmac_hash_type)
      .SetHmacTagSizeInBytes(params_proto.hmac_params().tag_size())
      .SetCiphertextSegmentSizeInBytes(params_proto.ciphertext_segment_size())
      .Build();
}

absl::StatusOr<ProtoAesCtrHmacStreamingParams> FromParameters(
    const AesCtrHmacStreamingParameters& parameters) {
  absl::StatusOr<HashTypeEnum> hkdf_hash_type =
      ToProtoHashType(parameters.HkdfHashType());
  if (!hkdf_hash_type.ok()) {
    return hkdf_hash_type.status();
  }
  absl::StatusOr<HashTypeEnum> hmac_hash_type =
      ToProtoHashType(parameters.HmacHashType());
  if (!hmac_hash_type.ok()) {
    return hmac_hash_type.status();
  }

  ProtoAesCtrHmacStreamingParams params;
  params.set_derived_key_size(parameters.DerivedKeySizeInBytes());
  params.set_hkdf_hash_type(*hkdf_hash_type);
  params.mutable_hmac_params()->set_hash(*hmac_hash_type);
  params.mutable_hmac_params()->set_tag_size(parameters.HmacTagSizeInBytes());
  params.set_ciphertext_segment_size(parameters.CiphertextSegmentSizeInBytes());
  return params;
}

absl::StatusOr<AesCtrHmacStreamingParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateStruct& key_template = serialization.GetKeyTemplateStruct();
  if (key_template.type_url != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesCtrHmacStreamingParameters.");
  }
  ProtoAesCtrHmacStreamingKeyFormat key_format_proto;
  if (!key_format_proto.ParseFromString(key_template.value)) {
    return absl::InvalidArgumentError(
        "Failed to parse AesCtrHmacStreamingKeyFormat proto");
  }
  if (key_format_proto.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing AesCtrHmacStreamingKeyFormat failed: only "
        "version 0 is accepted.");
  }
  return ToParameters(key_format_proto.params(), key_format_proto.key_size());
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const AesCtrHmacStreamingParameters& parameters) {
  absl::StatusOr<ProtoAesCtrHmacStreamingParams> params_proto =
      FromParameters(parameters);
  if (!params_proto.ok()) {
    return params_proto.status();
  }
  ProtoAesCtrHmacStreamingKeyFormat format;
  format.set_version(0);
  format.set_key_size(parameters.KeySizeInBytes());
  *format.mutable_params() = *params_proto;

  return ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixTypeEnum::kRaw, format.SerializeAsString());
}

absl::StatusOr<AesCtrHmacStreamingKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing AesCtrHmacStreamingKey.");
  }

  ProtoAesCtrHmacStreamingKey key_proto;
  if (!key_proto.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError(
        "Failed to parse AesCtrHmacStreamingKey proto");
  }

  if (key_proto.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing AesCtrHmacStreamingKey failed: only version 0 is accepted.");
  }

  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      ToParameters(key_proto.params(), key_proto.key_value().size());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return AesCtrHmacStreamingKey::Create(
      *parameters, RestrictedData(key_proto.key_value(), *token),
      GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const AesCtrHmacStreamingKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required.");
  }
  absl::StatusOr<RestrictedData> initial_key_material =
      key.GetInitialKeyMaterial(GetPartialKeyAccess());
  if (!initial_key_material.ok()) {
    return initial_key_material.status();
  }
  absl::StatusOr<ProtoAesCtrHmacStreamingParams> params_proto =
      FromParameters(key.GetParameters());
  if (!params_proto.ok()) {
    return params_proto.status();
  }

  ProtoAesCtrHmacStreamingKey key_proto;
  key_proto.set_version(0);
  *key_proto.mutable_params() = *params_proto;
  key_proto.set_key_value(initial_key_material->Get(*token));

  return ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(key_proto.SerializeAsSecretData(), *token),
      KeyMaterialTypeEnum::kSymmetric, OutputPrefixTypeEnum::kRaw,
      key.GetIdRequirement());
}

AesCtrHmacStreamingProtoParametersParserImpl*
AesCtrHmacStreamingProtoParametersParser() {
  static auto* parser = new AesCtrHmacStreamingProtoParametersParserImpl(
      kTypeUrl, ParseParameters);
  return parser;
}

AesCtrHmacStreamingProtoParametersSerializerImpl*
AesCtrHmacStreamingProtoParametersSerializer() {
  static auto* serializer =
      new AesCtrHmacStreamingProtoParametersSerializerImpl(kTypeUrl,
                                                           SerializeParameters);
  return serializer;
}

AesCtrHmacStreamingProtoKeyParserImpl* AesCtrHmacStreamingProtoKeyParser() {
  static auto* parser =
      new AesCtrHmacStreamingProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesCtrHmacStreamingProtoKeySerializerImpl*
AesCtrHmacStreamingProtoKeySerializer() {
  static auto* serializer =
      new AesCtrHmacStreamingProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterAesCtrHmacStreamingProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status = registry.RegisterParametersParser(
      AesCtrHmacStreamingProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      AesCtrHmacStreamingProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(AesCtrHmacStreamingProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(
      AesCtrHmacStreamingProtoKeySerializer());
}

absl::Status RegisterAesCtrHmacStreamingProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status = builder.RegisterParametersParser(
      AesCtrHmacStreamingProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterParametersSerializer(
      AesCtrHmacStreamingProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(AesCtrHmacStreamingProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(AesCtrHmacStreamingProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
