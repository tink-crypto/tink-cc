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

#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_ctr_hmac_aead_key.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/proto_parser.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;
using ::crypto::tink::util::SecretData;

bool HashTypeValid(uint32_t c) { return 0 <= c && c <= 5; }

// Enum representing the proto enum `google.crypto.tink.HashType`.
enum class HashTypeEnum : uint32_t {
  kUnknownHash = 0,
  kSha1,
  kSha384,
  kSha256,
  kSha512,
  kSha224,
};

struct AesCtrParamsStruct {
  uint32_t iv_size;

  static ProtoParser<AesCtrParamsStruct> CreateParser() {
    return ProtoParserBuilder<AesCtrParamsStruct>()
        .AddUint32Field(1, &AesCtrParamsStruct::iv_size)
        .BuildOrDie();
  }
};

struct AesCtrKeyFormatStruct {
  AesCtrParamsStruct params;
  uint32_t key_size;

  static ProtoParser<AesCtrKeyFormatStruct> CreateParser() {
    return ProtoParserBuilder<AesCtrKeyFormatStruct>()
        .AddMessageField(1, &AesCtrKeyFormatStruct::params,
                         AesCtrParamsStruct::CreateParser())
        .AddUint32Field(2, &AesCtrKeyFormatStruct::key_size)
        .BuildOrDie();
  }
};

struct HmacParamsStruct {
  HashTypeEnum hash;
  uint32_t tag_size;

  static ProtoParser<HmacParamsStruct> CreateParser() {
    return ProtoParserBuilder<HmacParamsStruct>()
        .AddEnumField(1, &HmacParamsStruct::hash, &HashTypeValid)
        .AddUint32Field(2, &HmacParamsStruct::tag_size)
        .BuildOrDie();
  }
};

struct HmacKeyFormatStruct {
  HmacParamsStruct params;
  uint32_t key_size;
  uint32_t version;

  static ProtoParser<HmacKeyFormatStruct> CreateParser() {
    return ProtoParserBuilder<HmacKeyFormatStruct>()
        .AddMessageField(1, &HmacKeyFormatStruct::params,
                         HmacParamsStruct::CreateParser())
        .AddUint32Field(2, &HmacKeyFormatStruct::key_size)
        .AddUint32Field(3, &HmacKeyFormatStruct::version)
        .BuildOrDie();
  }
};

struct AesCtrHmacAeadKeyFormatStruct {
  AesCtrKeyFormatStruct aes_ctr_key_format;
  HmacKeyFormatStruct hmac_key_format;

  static const ProtoParser<AesCtrHmacAeadKeyFormatStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<AesCtrHmacAeadKeyFormatStruct>>
        parser{ProtoParserBuilder<AesCtrHmacAeadKeyFormatStruct>()
                   .AddMessageField(
                       1, &AesCtrHmacAeadKeyFormatStruct::aes_ctr_key_format,
                       AesCtrKeyFormatStruct::CreateParser())
                   .AddMessageField(
                       2, &AesCtrHmacAeadKeyFormatStruct::hmac_key_format,
                       HmacKeyFormatStruct::CreateParser())
                   .BuildOrDie()};
    return *parser;
  }
};

struct AesCtrKeyStruct {
  uint32_t version;
  AesCtrParamsStruct params;
  SecretData key_value;

  static ProtoParser<AesCtrKeyStruct> CreateParser() {
    return ProtoParserBuilder<AesCtrKeyStruct>()
        .AddUint32Field(1, &AesCtrKeyStruct::version)
        .AddMessageField(2, &AesCtrKeyStruct::params,
                         AesCtrParamsStruct::CreateParser())
        .AddBytesSecretDataField(3, &AesCtrKeyStruct::key_value)
        .BuildOrDie();
  }
};

struct HmacKeyStruct {
  uint32_t version;
  HmacParamsStruct params;
  SecretData key_value;

  static ProtoParser<HmacKeyStruct> CreateParser() {
    return ProtoParserBuilder<HmacKeyStruct>()
        .AddUint32Field(1, &HmacKeyStruct::version)
        .AddMessageField(2, &HmacKeyStruct::params,
                         HmacParamsStruct::CreateParser())
        .AddBytesSecretDataField(3, &HmacKeyStruct::key_value)
        .BuildOrDie();
  }
};

struct AesCtrHmacAeadKeyStruct {
  uint32_t version;
  AesCtrKeyStruct aes_ctr_key;
  HmacKeyStruct hmac_key;

  static const ProtoParser<AesCtrHmacAeadKeyStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<AesCtrHmacAeadKeyStruct>>
        parser{ProtoParserBuilder<AesCtrHmacAeadKeyStruct>()
                   .AddUint32Field(1, &AesCtrHmacAeadKeyStruct::version)
                   .AddMessageField(2, &AesCtrHmacAeadKeyStruct::aes_ctr_key,
                                    AesCtrKeyStruct::CreateParser())
                   .AddMessageField(3, &AesCtrHmacAeadKeyStruct::hmac_key,
                                    HmacKeyStruct::CreateParser())
                   .BuildOrDie()};
    return *parser;
  }
};

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

absl::StatusOr<HmacParamsStruct> GetHmacProtoParams(
    const AesCtrHmacAeadParameters& parameters) {
  absl::StatusOr<HashTypeEnum> hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }
  HmacParamsStruct hmac_params{
      /*hash=*/*hash_type,
      /*tag_size=*/static_cast<uint32_t>(parameters.GetTagSizeInBytes()),
  };
  return hmac_params;
}

absl::StatusOr<AesCtrHmacAeadParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return absl::InvalidArgumentError(
        absl::StrCat("Wrong type URL when parsing AesCtrHmacAeadParameters: ",
                     serialization.GetKeyTemplate().type_url()));
  }

  absl::StatusOr<AesCtrHmacAeadKeyFormatStruct> key_format_struct =
      AesCtrHmacAeadKeyFormatStruct::GetParser().Parse(
          serialization.GetKeyTemplate().value());
  if (!key_format_struct.ok()) {
    return key_format_struct.status();
  }

  if (key_format_struct->hmac_key_format.version != 0) {
    return absl::InvalidArgumentError(
        absl::StrCat("Failed to parse hmac key format: only version 0 "
                     "is accepted, got ",
                     key_format_struct->hmac_key_format.version));
  }

  absl::StatusOr<AesCtrHmacAeadParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplateStruct().output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<AesCtrHmacAeadParameters::HashType> hash_type =
      ToHashType(key_format_struct->hmac_key_format.params.hash);
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  return AesCtrHmacAeadParameters::Builder()
      .SetAesKeySizeInBytes(key_format_struct->aes_ctr_key_format.key_size)
      .SetHmacKeySizeInBytes(key_format_struct->hmac_key_format.key_size)
      .SetIvSizeInBytes(key_format_struct->aes_ctr_key_format.params.iv_size)
      .SetTagSizeInBytes(key_format_struct->hmac_key_format.params.tag_size)
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

  absl::StatusOr<HmacParamsStruct> hmac_params = GetHmacProtoParams(parameters);
  if (!hmac_params.ok()) {
    return hmac_params.status();
  }

  AesCtrHmacAeadKeyFormatStruct aes_ctr_hmac_aead_key_format;
  // AES-CTR key format.
  aes_ctr_hmac_aead_key_format.aes_ctr_key_format.params.iv_size =
      parameters.GetIvSizeInBytes();
  aes_ctr_hmac_aead_key_format.aes_ctr_key_format.key_size =
      parameters.GetAesKeySizeInBytes();
  // HMAC key format.
  aes_ctr_hmac_aead_key_format.hmac_key_format.version = 0;
  aes_ctr_hmac_aead_key_format.hmac_key_format.params = *hmac_params;
  aes_ctr_hmac_aead_key_format.hmac_key_format.key_size =
      parameters.GetHmacKeySizeInBytes();

  absl::StatusOr<std::string> serialized_proto =
      AesCtrHmacAeadKeyFormatStruct::GetParser().SerializeIntoString(
          aes_ctr_hmac_aead_key_format);
  if (!serialized_proto.ok()) {
    return serialized_proto.status();
  }

  return ProtoParametersSerialization::Create(kTypeUrl, *output_prefix_type,
                                              *serialized_proto);
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

  absl::StatusOr<AesCtrHmacAeadKeyStruct> key_struct =
      AesCtrHmacAeadKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!key_struct.ok()) {
    return absl::InvalidArgumentError(
        "Failed to parse AesCtrHmacAeadKey proto");
  }
  if (key_struct->version != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }
  if (key_struct->aes_ctr_key.version != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 keys inner AES CTR keys are accepted.");
  }
  if (key_struct->hmac_key.version != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 keys inner HMAC keys are accepted.");
  }

  absl::StatusOr<AesCtrHmacAeadParameters::Variant> variant = ToVariant(
      static_cast<OutputPrefixTypeEnum>(serialization.GetOutputPrefixType()));
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<AesCtrHmacAeadParameters::HashType> hash_type =
      ToHashType(key_struct->hmac_key.params.hash);
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(key_struct->aes_ctr_key.key_value.size())
          .SetHmacKeySizeInBytes(key_struct->hmac_key.key_value.size())
          .SetIvSizeInBytes(key_struct->aes_ctr_key.params.iv_size)
          .SetTagSizeInBytes(key_struct->hmac_key.params.tag_size)
          .SetHashType(*hash_type)
          .SetVariant(*variant)
          .Build();
  if (!parameters.ok()) {
    return parameters.status();
  }

  return AesCtrHmacAeadKey::Builder()
      .SetParameters(*parameters)
      .SetAesKeyBytes(RestrictedData(key_struct->aes_ctr_key.key_value, *token))
      .SetHmacKeyBytes(RestrictedData(key_struct->hmac_key.key_value, *token))
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

  AesCtrHmacAeadKeyStruct key_struct;
  key_struct.version = 0;

  // AES-CTR key.
  key_struct.aes_ctr_key.version = 0;
  key_struct.aes_ctr_key.params.iv_size =
      key.GetParameters().GetIvSizeInBytes();
  key_struct.aes_ctr_key.key_value =
      key.GetAesKeyBytes(GetPartialKeyAccess()).Get(*token);

  // HMAC key.
  absl::StatusOr<HmacParamsStruct> hmac_params =
      GetHmacProtoParams(key.GetParameters());
  if (!hmac_params.ok()) {
    return hmac_params.status();
  }

  key_struct.hmac_key.version = 0;
  key_struct.hmac_key.params = *hmac_params;
  key_struct.hmac_key.key_value =
      key.GetHmacKeyBytes(GetPartialKeyAccess()).Get(*token);

  absl::StatusOr<SecretData> serialized_proto =
      AesCtrHmacAeadKeyStruct::GetParser().SerializeIntoSecretData(key_struct);
  if (!serialized_proto.ok()) {
    return serialized_proto.status();
  }

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  return ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(*std::move(serialized_proto), *token),
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
