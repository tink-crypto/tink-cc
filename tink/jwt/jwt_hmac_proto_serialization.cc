// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/jwt_hmac_proto_serialization.h"

#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/no_destructor.h"
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
#include "tink/internal/proto_parser.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/jwt/jwt_hmac_key.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;

using JwtHmacProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   JwtHmacParameters>;
using JwtHmacProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<JwtHmacParameters,
                                       internal::ProtoParametersSerialization>;
using JwtHmacProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, JwtHmacKey>;
using JwtHmacProtoKeySerializerImpl =
    internal::KeySerializerImpl<JwtHmacKey, internal::ProtoKeySerialization>;

struct CustomKidStruct {
  std::string value;

  static ProtoParser<CustomKidStruct> CreateParser() {
    return ProtoParserBuilder<CustomKidStruct>()
        .AddBytesStringField(1, &CustomKidStruct::value)
        .BuildOrDie();
  }
};

bool JwtHmacAlgorithmValid(int value) { return value >= 0 && value <= 3; }

enum class JwtHmacAlgorithmEnum : uint32_t {
  kHsUnknown = 0,
  kHS256 = 1,
  kHS384 = 2,
  kHS512 = 3,
};

struct JwtHmacKeyStruct {
  uint32_t version;
  JwtHmacAlgorithmEnum algorithm;
  util::SecretData key_value;
  absl::optional<CustomKidStruct> custom_kid;

  static const ProtoParser<JwtHmacKeyStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<JwtHmacKeyStruct>> parser{
        ProtoParserBuilder<JwtHmacKeyStruct>()
            .AddUint32Field(1, &JwtHmacKeyStruct::version)
            .AddEnumField(2, &JwtHmacKeyStruct::algorithm,
                          &JwtHmacAlgorithmValid)
            .AddBytesSecretDataField(3, &JwtHmacKeyStruct::key_value)
            .AddMessageFieldWithPresence(4, &JwtHmacKeyStruct::custom_kid,
                                         CustomKidStruct::CreateParser())

            .BuildOrDie()};
    return *parser;
  }
};

struct JwtHmacKeyFormatStruct {
  uint32_t version;
  JwtHmacAlgorithmEnum algorithm;
  uint32_t key_size;

  static const ProtoParser<JwtHmacKeyFormatStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<JwtHmacKeyFormatStruct>> parser{
        ProtoParserBuilder<JwtHmacKeyFormatStruct>()
            .AddUint32Field(1, &JwtHmacKeyFormatStruct::version)
            .AddEnumField(2, &JwtHmacKeyFormatStruct::algorithm,
                          &JwtHmacAlgorithmValid)
            .AddUint32Field(3, &JwtHmacKeyFormatStruct::key_size)
            .BuildOrDie()};
    return *parser;
  }
};

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtHmacKey";

absl::StatusOr<JwtHmacParameters::KidStrategy> ToKidStrategy(
    internal::OutputPrefixTypeEnum output_prefix_type, bool has_custom_kid) {
  switch (output_prefix_type) {
    case internal::OutputPrefixTypeEnum::kRaw:
      if (has_custom_kid) {
        return JwtHmacParameters::KidStrategy::kCustom;
      }
      return JwtHmacParameters::KidStrategy::kIgnored;
    case internal::OutputPrefixTypeEnum::kTink:
      return JwtHmacParameters::KidStrategy::kBase64EncodedKeyId;
    default:
      return absl::InvalidArgumentError(
          "Invalid OutputPrefixType for JwtHmacKeyFormat.");
  }
}

absl::StatusOr<internal::OutputPrefixTypeEnum> ToOutputPrefixType(
    JwtHmacParameters::KidStrategy kid_strategy) {
  switch (kid_strategy) {
    case JwtHmacParameters::KidStrategy::kCustom:
      return internal::OutputPrefixTypeEnum::kRaw;
    case JwtHmacParameters::KidStrategy::kIgnored:
      return internal::OutputPrefixTypeEnum::kRaw;
    case JwtHmacParameters::KidStrategy::kBase64EncodedKeyId:
      return internal::OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine JwtHmacParameters::KidStrategy.");
  }
}

absl::StatusOr<JwtHmacParameters::Algorithm> FromProtoAlgorithm(
    JwtHmacAlgorithmEnum algorithm) {
  switch (algorithm) {
    case JwtHmacAlgorithmEnum::kHS256:
      return JwtHmacParameters::Algorithm::kHs256;
    case JwtHmacAlgorithmEnum::kHS384:
      return JwtHmacParameters::Algorithm::kHs384;
    case JwtHmacAlgorithmEnum::kHS512:
      return JwtHmacParameters::Algorithm::kHs512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine JwtHmacAlgorithm.");
  }
}

absl::StatusOr<JwtHmacAlgorithmEnum> ToProtoAlgorithm(
    JwtHmacParameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtHmacParameters::Algorithm::kHs256:
      return JwtHmacAlgorithmEnum::kHS256;
    case JwtHmacParameters::Algorithm::kHs384:
      return JwtHmacAlgorithmEnum::kHS384;
    case JwtHmacParameters::Algorithm::kHs512:
      return JwtHmacAlgorithmEnum::kHS512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine JwtHmacParameters::Algorithm");
  }
}

absl::StatusOr<JwtHmacParameters> ToParameters(
    int key_size_in_bytes, internal::OutputPrefixTypeEnum output_prefix_type,
    JwtHmacAlgorithmEnum proto_algorithm, bool has_custom_kid) {
  absl::StatusOr<JwtHmacParameters::KidStrategy> kid_strategy =
      ToKidStrategy(output_prefix_type, has_custom_kid);
  if (!kid_strategy.ok()) {
    return kid_strategy.status();
  }
  absl::StatusOr<JwtHmacParameters::Algorithm> algorithm =
      FromProtoAlgorithm(proto_algorithm);
  if (!algorithm.ok()) {
    return algorithm.status();
  }
  return JwtHmacParameters::Create(key_size_in_bytes, *kid_strategy,
                                   *algorithm);
}

absl::StatusOr<JwtHmacParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  const internal::KeyTemplateStruct& key_template =
      serialization.GetKeyTemplateStruct();
  if (key_template.type_url != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtHmacParameters.");
  }
  absl::StatusOr<JwtHmacKeyFormatStruct> key_format_struct =
      JwtHmacKeyFormatStruct::GetParser().Parse(key_template.value);
  if (!key_format_struct.ok()) {
    return key_format_struct.status();
  }

  if (key_format_struct->version != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtHmacParameters failed: only version 0 is accepted.");
  }

  return ToParameters(key_format_struct->key_size,
                      serialization.GetKeyTemplateStruct().output_prefix_type,
                      key_format_struct->algorithm, /*has_custom_kid=*/false);
}

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const JwtHmacParameters& parameters) {
  if (parameters.GetKidStrategy() == JwtHmacParameters::KidStrategy::kCustom) {
    return absl::InvalidArgumentError(
        "Unable to serialize JwtHmacParameters::KidStrategy::kCustom.");
  }
  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  absl::StatusOr<JwtHmacAlgorithmEnum> proto_algorithm =
      ToProtoAlgorithm(parameters.GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  JwtHmacKeyFormatStruct key_format_struct;
  key_format_struct.version = 0;
  key_format_struct.key_size = parameters.KeySizeInBytes();
  key_format_struct.algorithm = *proto_algorithm;

  absl::StatusOr<std::string> serialized_key_format =
      JwtHmacKeyFormatStruct::GetParser().SerializeIntoString(
          key_format_struct);
  if (!serialized_key_format.ok()) {
    return serialized_key_format.status();
  }

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, *serialized_key_format);
}

absl::StatusOr<JwtHmacKey> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::InvalidArgumentError("SecretKeyAccess is required.");
  }
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtHmacKey.");
  }
  absl::StatusOr<JwtHmacKeyStruct> key_struct =
      JwtHmacKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!key_struct.ok()) {
    return key_struct.status();
  }

  if (key_struct->version != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtHmacKey failed: only version 0 is accepted.");
  }

  absl::StatusOr<JwtHmacParameters> parameters = ToParameters(
      key_struct->key_value.size(), serialization.GetOutputPrefixTypeEnum(),
      key_struct->algorithm, key_struct->custom_kid.has_value());
  if (!parameters.ok()) {
    return parameters.status();
  }

  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetParameters(*parameters)
          .SetKeyBytes(RestrictedData(key_struct->key_value, *token));
  if (serialization.IdRequirement().has_value()) {
    builder.SetIdRequirement(*serialization.IdRequirement());
  }
  if (key_struct->custom_kid.has_value()) {
    builder.SetCustomKid(key_struct->custom_kid.value().value);
  }
  return builder.Build(GetPartialKeyAccess());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const JwtHmacKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::InvalidArgumentError("SecretKeyAccess is required.");
  }
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }
  absl::StatusOr<JwtHmacAlgorithmEnum> proto_algorithm =
      ToProtoAlgorithm(key.GetParameters().GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  JwtHmacKeyStruct key_struct;
  key_struct.version = 0;
  key_struct.key_value = restricted_input->Get(*token);
  key_struct.algorithm = *proto_algorithm;
  if (key.GetParameters().GetKidStrategy() ==
      JwtHmacParameters::KidStrategy::kCustom) {
    key_struct.custom_kid = CustomKidStruct{key.GetKid().value()};
  }

  absl::StatusOr<util::SecretData> serialized_key =
      JwtHmacKeyStruct::GetParser().SerializeIntoSecretData(key_struct);
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output =
      RestrictedData(*std::move(serialized_key), *token);
  return internal::ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, internal::KeyMaterialTypeEnum::kSymmetric,
      *output_prefix_type, key.GetIdRequirement());
}

JwtHmacProtoParametersParserImpl* JwtHmacProtoParametersParser() {
  static auto* parser =
      new JwtHmacProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

JwtHmacProtoParametersSerializerImpl* JwtHmacProtoParametersSerializer() {
  static auto* serializer =
      new JwtHmacProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

JwtHmacProtoKeyParserImpl* JwtHmacProtoKeyParser() {
  static auto* parser = new JwtHmacProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

JwtHmacProtoKeySerializerImpl* JwtHmacProtoKeySerializer() {
  static auto* serializer = new JwtHmacProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterJwtHmacProtoSerialization() {
  absl::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(JwtHmacProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersSerializer(JwtHmacProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(JwtHmacProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(JwtHmacProtoKeySerializer());
}

}  // namespace tink
}  // namespace crypto
