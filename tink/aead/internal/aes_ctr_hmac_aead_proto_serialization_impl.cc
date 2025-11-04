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

#include "tink/aead/internal/aes_ctr_hmac_aead_proto_serialization_impl.h"

#include <utility>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_ctr_hmac_aead_key.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/internal/aes_ctr_hmac_proto_structs.h"
#include "tink/internal/common_proto_enums.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/mac/internal/hmac_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using AesCtrHmacAeadProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization,
                         AesCtrHmacAeadParameters>;
using AesCtrHmacAeadProtoParametersSerializerImpl =
    ParametersSerializerImpl<AesCtrHmacAeadParameters,
                             ProtoParametersSerialization>;
using AesCtrHmacAeadProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, AesCtrHmacAeadKey>;
using AesCtrHmacAeadProtoKeySerializerImpl =
    KeySerializerImpl<AesCtrHmacAeadKey, ProtoKeySerialization>;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";

absl::StatusOr<AesCtrHmacAeadParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixTypeEnum::kCrunchy:
      return AesCtrHmacAeadParameters::Variant::kCrunchy;
    case OutputPrefixTypeEnum::kRaw:
      return AesCtrHmacAeadParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return AesCtrHmacAeadParameters::Variant::kTink;
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine AesCtrHmacAeadParameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    AesCtrHmacAeadParameters::Variant variant) {
  switch (variant) {
    case AesCtrHmacAeadParameters::Variant::kCrunchy:
      return OutputPrefixTypeEnum::kCrunchy;
    case AesCtrHmacAeadParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case AesCtrHmacAeadParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

absl::StatusOr<AesCtrHmacAeadParameters::HashType> ToHashType(
    HashTypeEnum hash_type) {
  switch (hash_type) {
    case HashTypeEnum::kSha1:
      return AesCtrHmacAeadParameters::HashType::kSha1;
    case HashTypeEnum::kSha224:
      return AesCtrHmacAeadParameters::HashType::kSha224;
    case HashTypeEnum::kSha256:
      return AesCtrHmacAeadParameters::HashType::kSha256;
    case HashTypeEnum::kSha384:
      return AesCtrHmacAeadParameters::HashType::kSha384;
    case HashTypeEnum::kSha512:
      return AesCtrHmacAeadParameters::HashType::kSha512;
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine AesCtrHmacAeadParameters::HashType");
  }
}

absl::StatusOr<HashTypeEnum> ToProtoHashType(
    AesCtrHmacAeadParameters::HashType hash_type) {
  switch (hash_type) {
    case AesCtrHmacAeadParameters::HashType::kSha1:
      return HashTypeEnum::kSha1;
    case AesCtrHmacAeadParameters::HashType::kSha224:
      return HashTypeEnum::kSha224;
    case AesCtrHmacAeadParameters::HashType::kSha256:
      return HashTypeEnum::kSha256;
    case AesCtrHmacAeadParameters::HashType::kSha384:
      return HashTypeEnum::kSha384;
    case AesCtrHmacAeadParameters::HashType::kSha512:
      return HashTypeEnum::kSha512;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HashType");
  }
}

absl::StatusOr<AesCtrHmacAeadParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const internal::KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kTypeUrl) {
    return absl::InvalidArgumentError(
        absl::StrCat("Wrong type URL when parsing AesCtrHmacAeadParameters: ",
                     key_template.type_url()));
  }

  AesCtrHmacAeadKeyFormatTP key_format;
  if (!key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError(
        "Failed to parse AesCtrHmacAeadKeyFormat proto");
  }

  if (key_format.hmac_key_format().version() != 0) {
    return absl::InvalidArgumentError(
        absl::StrCat("Failed to parse hmac key format: only version 0 "
                     "is accepted, got ",
                     key_format.hmac_key_format().version()));
  }

  absl::StatusOr<AesCtrHmacAeadParameters::Variant> variant =
      ToVariant(key_template.output_prefix_type());
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<AesCtrHmacAeadParameters::HashType> hash_type =
      ToHashType(key_format.hmac_key_format().params().hash());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  return AesCtrHmacAeadParameters::Builder()
      .SetAesKeySizeInBytes(key_format.aes_ctr_key_format().key_size())
      .SetHmacKeySizeInBytes(key_format.hmac_key_format().key_size())
      .SetIvSizeInBytes(key_format.aes_ctr_key_format().params().iv_size())
      .SetTagSizeInBytes(key_format.hmac_key_format().params().tag_size())
      .SetHashType(*hash_type)
      .SetVariant(*variant)
      .Build();
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const AesCtrHmacAeadParameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<HashTypeEnum> hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  AesCtrHmacAeadKeyFormatTP key_format;
  key_format.mutable_aes_ctr_key_format()->mutable_params()->set_iv_size(
      parameters.GetIvSizeInBytes());
  key_format.mutable_aes_ctr_key_format()->set_key_size(
      parameters.GetAesKeySizeInBytes());
  key_format.mutable_hmac_key_format()->set_version(0);
  key_format.mutable_hmac_key_format()->mutable_params()->set_hash(*hash_type);
  key_format.mutable_hmac_key_format()->mutable_params()->set_tag_size(
      parameters.GetTagSizeInBytes());
  key_format.mutable_hmac_key_format()->set_key_size(
      parameters.GetHmacKeySizeInBytes());

  return ProtoParametersSerialization::Create(kTypeUrl, *output_prefix_type,
                                              key_format.SerializeAsString());
}

absl::StatusOr<AesCtrHmacAeadKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesCtrHmacAeadKey.");
  }
  if (!token.has_value()) {
    return absl::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  AesCtrHmacAeadKeyTP key;
  if (!key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError(
        "Failed to parse AesCtrHmacAeadKey proto");
  }
  if (key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }
  if (key.aes_ctr_key().version() != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 keys inner AES CTR keys are accepted.");
  }
  if (key.hmac_key().version() != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 keys inner HMAC keys are accepted.");
  }

  absl::StatusOr<AesCtrHmacAeadParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixTypeEnum());
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<AesCtrHmacAeadParameters::HashType> hash_type =
      ToHashType(key.hmac_key().params().hash());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(key.aes_ctr_key().key_value().size())
          .SetHmacKeySizeInBytes(key.hmac_key().key_value().size())
          .SetIvSizeInBytes(key.aes_ctr_key().params().iv_size())
          .SetTagSizeInBytes(key.hmac_key().params().tag_size())
          .SetHashType(*hash_type)
          .SetVariant(*variant)
          .Build();
  if (!parameters.ok()) {
    return parameters.status();
  }

  return AesCtrHmacAeadKey::Builder()
      .SetParameters(*parameters)
      .SetAesKeyBytes(
          RestrictedData(std::move(key.aes_ctr_key().key_value()), *token))
      .SetHmacKeyBytes(
          RestrictedData(std::move(key.hmac_key().key_value()), *token))
      .SetIdRequirement(serialization.IdRequirement())
      .Build(GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const AesCtrHmacAeadKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  absl::StatusOr<RestrictedData> restricted_aes_input =
      key.GetAesKeyBytes(GetPartialKeyAccess());
  if (!restricted_aes_input.ok()) {
    return restricted_aes_input.status();
  }

  absl::StatusOr<RestrictedData> restricted_hmac_input =
      key.GetHmacKeyBytes(GetPartialKeyAccess());
  if (!restricted_hmac_input.ok()) {
    return restricted_hmac_input.status();
  }

  absl::StatusOr<HashTypeEnum> hash_type =
      ToProtoHashType(key.GetParameters().GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  AesCtrHmacAeadKeyTP proto_key;
  proto_key.set_version(0);
  proto_key.mutable_aes_ctr_key()->set_version(0);
  proto_key.mutable_aes_ctr_key()->mutable_params()->set_iv_size(
      key.GetParameters().GetIvSizeInBytes());
  proto_key.mutable_aes_ctr_key()->set_key_value(
      restricted_aes_input->GetSecret(*token));

  proto_key.mutable_hmac_key()->set_version(0);
  proto_key.mutable_hmac_key()->mutable_params()->set_hash(*hash_type);
  proto_key.mutable_hmac_key()->mutable_params()->set_tag_size(
      key.GetParameters().GetTagSizeInBytes());
  proto_key.mutable_hmac_key()->set_key_value(
      restricted_hmac_input->GetSecret(*token));

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  SecretData serialized_key = proto_key.SerializeAsSecretData();
  return ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(std::move(serialized_key), *token),
      KeyMaterialTypeEnum::kSymmetric, *output_prefix_type,
      key.GetIdRequirement());
}

AesCtrHmacAeadProtoParametersParserImpl& AesCtrHmacAeadProtoParametersParser() {
  static auto* parser =
      new AesCtrHmacAeadProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return *parser;
}

AesCtrHmacAeadProtoParametersSerializerImpl&
AesCtrHmacAeadProtoParametersSerializer() {
  static auto* serializer = new AesCtrHmacAeadProtoParametersSerializerImpl(
      kTypeUrl, SerializeParameters);
  return *serializer;
}

AesCtrHmacAeadProtoKeyParserImpl& AesCtrHmacAeadProtoKeyParser() {
  static auto* parser =
      new AesCtrHmacAeadProtoKeyParserImpl(kTypeUrl, ParseKey);
  return *parser;
}

AesCtrHmacAeadProtoKeySerializerImpl& AesCtrHmacAeadProtoKeySerializer() {
  static auto* serializer =
      new AesCtrHmacAeadProtoKeySerializerImpl(SerializeKey);
  return *serializer;
}

}  // namespace

absl::Status RegisterAesCtrHmacAeadProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(&AesCtrHmacAeadProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      &AesCtrHmacAeadProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(&AesCtrHmacAeadProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(&AesCtrHmacAeadProtoKeySerializer());
}

absl::Status RegisterAesCtrHmacAeadProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(&AesCtrHmacAeadProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterParametersSerializer(
      &AesCtrHmacAeadProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(&AesCtrHmacAeadProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(&AesCtrHmacAeadProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
