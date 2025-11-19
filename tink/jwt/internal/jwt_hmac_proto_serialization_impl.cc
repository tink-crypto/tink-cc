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

#include "tink/jwt/internal/jwt_hmac_proto_serialization_impl.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
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
#include "tink/internal/proto_parser_enum_field.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_secret_data_field.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/jwt/jwt_hmac_key.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::BytesField;
using ::crypto::tink::internal::proto_parsing::EnumField;
using ::crypto::tink::internal::proto_parsing::Field;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageField;
using ::crypto::tink::internal::proto_parsing::SecretDataField;
using ::crypto::tink::internal::proto_parsing::Uint32Field;

using JwtHmacProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, JwtHmacParameters>;
using JwtHmacProtoParametersSerializerImpl =
    ParametersSerializerImpl<JwtHmacParameters, ProtoParametersSerialization>;
using JwtHmacProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, JwtHmacKey>;
using JwtHmacProtoKeySerializerImpl =
    KeySerializerImpl<JwtHmacKey, ProtoKeySerialization>;

class JwtHmacCustomKidTP : public Message {
 public:
  JwtHmacCustomKidTP() = default;
  using Message::SerializeAsString;

  const std::string& value() const { return value_.value(); }
  void set_value(absl::string_view value) { value_.set_value(value); }

 private:
  size_t num_fields() const override { return 1; }
  const Field* field(int i) const override {
    return std::array<const Field*, 1>{&value_}[i];
  }

  BytesField value_{1};
};

bool JwtHmacAlgorithmValid(int value) { return value >= 0 && value <= 3; }

enum class JwtHmacAlgorithmEnum : uint32_t {
  kHsUnknown = 0,
  kHS256 = 1,
  kHS384 = 2,
  kHS512 = 3,
};

class JwtHmacKeyTP : public Message {
 public:
  JwtHmacKeyTP() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  JwtHmacAlgorithmEnum algorithm() const { return algorithm_.value(); }
  void set_algorithm(JwtHmacAlgorithmEnum algorithm) {
    algorithm_.set_value(algorithm);
  }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(SecretData key_value) {
    *key_value_.mutable_value() = std::move(key_value);
  }

  const JwtHmacCustomKidTP& custom_kid() const { return custom_kid_.value(); }
  bool has_custom_kid() const { return custom_kid_.has_value(); }
  JwtHmacCustomKidTP* mutable_custom_kid() {
    return custom_kid_.mutable_value();
  }
  void set_custom_kid(const JwtHmacCustomKidTP& custom_kid) {
    *custom_kid_.mutable_value() = custom_kid;
  }

 private:
  size_t num_fields() const override { return 4; }
  const Field* field(int i) const override {
    return std::array<const Field*, 4>{&version_, &algorithm_, &key_value_,
                                       &custom_kid_}[i];
  }

  Uint32Field version_{1};
  EnumField<JwtHmacAlgorithmEnum> algorithm_{2, &JwtHmacAlgorithmValid};
  SecretDataField key_value_{3};
  MessageField<JwtHmacCustomKidTP> custom_kid_{4};
};

class JwtHmacKeyFormatTP : public Message {
 public:
  JwtHmacKeyFormatTP() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  JwtHmacAlgorithmEnum algorithm() const { return algorithm_.value(); }
  void set_algorithm(JwtHmacAlgorithmEnum algorithm) {
    algorithm_.set_value(algorithm);
  }

  uint32_t key_size() const { return key_size_.value(); }
  void set_key_size(uint32_t key_size) { key_size_.set_value(key_size); }

 private:
  size_t num_fields() const override { return 3; }
  const Field* field(int i) const override {
    return std::array<const Field*, 3>{&version_, &algorithm_, &key_size_}[i];
  }

  Uint32Field version_{1};
  EnumField<JwtHmacAlgorithmEnum> algorithm_{2, &JwtHmacAlgorithmValid};
  Uint32Field key_size_{3};
};

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtHmacKey";

absl::StatusOr<JwtHmacParameters::KidStrategy> ToKidStrategy(
    OutputPrefixTypeEnum output_prefix_type, bool has_custom_kid) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kRaw:
      if (has_custom_kid) {
        return JwtHmacParameters::KidStrategy::kCustom;
      }
      return JwtHmacParameters::KidStrategy::kIgnored;
    case OutputPrefixTypeEnum::kTink:
      return JwtHmacParameters::KidStrategy::kBase64EncodedKeyId;
    default:
      return absl::InvalidArgumentError(
          "Invalid OutputPrefixType for JwtHmacKeyFormat.");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    JwtHmacParameters::KidStrategy kid_strategy) {
  switch (kid_strategy) {
    case JwtHmacParameters::KidStrategy::kCustom:
      return OutputPrefixTypeEnum::kRaw;
    case JwtHmacParameters::KidStrategy::kIgnored:
      return OutputPrefixTypeEnum::kRaw;
    case JwtHmacParameters::KidStrategy::kBase64EncodedKeyId:
      return OutputPrefixTypeEnum::kTink;
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
    int key_size_in_bytes, OutputPrefixTypeEnum output_prefix_type,
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
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtHmacParameters.");
  }
  JwtHmacKeyFormatTP proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError("Failed to parse JwtHmacKeyFormat proto");
  }

  if (proto_key_format.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtHmacParameters failed: only version 0 is accepted.");
  }

  return ToParameters(proto_key_format.key_size(),
                      key_template.output_prefix_type(),
                      proto_key_format.algorithm(), /*has_custom_kid=*/false);
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const JwtHmacParameters& parameters) {
  if (parameters.GetKidStrategy() == JwtHmacParameters::KidStrategy::kCustom) {
    return absl::InvalidArgumentError(
        "Unable to serialize JwtHmacParameters::KidStrategy::kCustom.");
  }
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  absl::StatusOr<JwtHmacAlgorithmEnum> proto_algorithm =
      ToProtoAlgorithm(parameters.GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  JwtHmacKeyFormatTP proto_key_format;
  proto_key_format.set_version(0);
  proto_key_format.set_key_size(parameters.KeySizeInBytes());
  proto_key_format.set_algorithm(*proto_algorithm);

  return ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

absl::StatusOr<JwtHmacKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::InvalidArgumentError("SecretKeyAccess is required.");
  }
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtHmacKey.");
  }
  JwtHmacKeyTP proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse JwtHmacKey proto");
  }

  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtHmacKey failed: only version 0 is accepted.");
  }

  absl::StatusOr<JwtHmacParameters> parameters = ToParameters(
      proto_key.key_value().size(), serialization.GetOutputPrefixTypeEnum(),
      proto_key.algorithm(), proto_key.has_custom_kid());
  if (!parameters.ok()) {
    return parameters.status();
  }

  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetParameters(*parameters)
          .SetKeyBytes(RestrictedData(proto_key.key_value(), *token));
  if (serialization.IdRequirement().has_value()) {
    builder.SetIdRequirement(*serialization.IdRequirement());
  }
  if (proto_key.has_custom_kid()) {
    builder.SetCustomKid(proto_key.custom_kid().value());
  }
  return builder.Build(GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
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

  JwtHmacKeyTP proto_key;
  proto_key.set_version(0);
  proto_key.set_key_value(restricted_input->Get(*token));
  proto_key.set_algorithm(*proto_algorithm);
  if (key.GetParameters().GetKidStrategy() ==
      JwtHmacParameters::KidStrategy::kCustom) {
    proto_key.mutable_custom_kid()->set_value(*key.GetKid());
  }

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(proto_key.SerializeAsSecretData(), *token),
      KeyMaterialTypeEnum::kSymmetric, *output_prefix_type,
      key.GetIdRequirement());
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

absl::Status RegisterJwtHmacProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  if (absl::Status status =
          registry.RegisterParametersParser(JwtHmacProtoParametersParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = registry.RegisterParametersSerializer(
          JwtHmacProtoParametersSerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = registry.RegisterKeyParser(JwtHmacProtoKeyParser());
      !status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(JwtHmacProtoKeySerializer());
}

absl::Status RegisterJwtHmacProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  if (absl::Status status =
          builder.RegisterParametersParser(JwtHmacProtoParametersParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = builder.RegisterParametersSerializer(
          JwtHmacProtoParametersSerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = builder.RegisterKeyParser(JwtHmacProtoKeyParser());
      !status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(JwtHmacProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
