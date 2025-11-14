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

#include "tink/jwt/internal/jwt_ecdsa_proto_serialization_impl.h"

#include <array>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_encoding_util.h"
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
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_private_key.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
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

class JwtEcdsaCustomKidTP : public Message<JwtEcdsaCustomKidTP> {
 public:
  JwtEcdsaCustomKidTP() = default;
  using Message::SerializeAsString;

  const std::string& value() const { return value_.value(); }
  void set_value(absl::string_view value) { value_.set_value(value); }

  std::array<const Field*, 1> GetFields() const { return {&value_}; }

 private:
  BytesField<std::string> value_{1};
};

bool JwtEcdsaAlgorithmValid(int value) { return value >= 0 && value <= 3; }

enum class JwtEcdsaAlgorithmEnum : uint32_t {
  kEsUnknown = 0,
  kEs256 = 1,
  kEs384 = 2,
  kEs512 = 3,
};

class JwtEcdsaPublicKeyTP : public Message<JwtEcdsaPublicKeyTP> {
 public:
  JwtEcdsaPublicKeyTP() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  JwtEcdsaAlgorithmEnum algorithm() const { return algorithm_.value(); }
  void set_algorithm(JwtEcdsaAlgorithmEnum algorithm) {
    algorithm_.set_value(algorithm);
  }

  const std::string& x() const { return x_.value(); }
  void set_x(absl::string_view x) { x_.set_value(x); }

  const std::string& y() const { return y_.value(); }
  void set_y(absl::string_view y) { y_.set_value(y); }

  const JwtEcdsaCustomKidTP& custom_kid() const { return custom_kid_.value(); }
  bool has_custom_kid() const { return custom_kid_.has_value(); }
  JwtEcdsaCustomKidTP* mutable_custom_kid() {
    return custom_kid_.mutable_value();
  }
  void set_custom_kid(const JwtEcdsaCustomKidTP& custom_kid) {
    *custom_kid_.mutable_value() = custom_kid;
  }

  std::array<const Field*, 5> GetFields() const {
    return {&version_, &algorithm_, &x_, &y_, &custom_kid_};
  }

 private:
  Uint32Field version_{1};
  EnumField<JwtEcdsaAlgorithmEnum> algorithm_{2, &JwtEcdsaAlgorithmValid};
  BytesField<std::string> x_{3};
  BytesField<std::string> y_{4};
  MessageField<JwtEcdsaCustomKidTP> custom_kid_{5};
};

class JwtEcdsaPrivateKeyTP : public Message<JwtEcdsaPrivateKeyTP> {
 public:
  JwtEcdsaPrivateKeyTP() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const JwtEcdsaPublicKeyTP& public_key() const { return public_key_.value(); }
  JwtEcdsaPublicKeyTP* mutable_public_key() {
    return public_key_.mutable_value();
  }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(SecretData key_value) {
    *key_value_.mutable_value() = std::move(key_value);
  }

  std::array<const Field*, 3> GetFields() const {
    return {&version_, &public_key_, &key_value_};
  }

 private:
  Uint32Field version_{1};
  MessageField<JwtEcdsaPublicKeyTP> public_key_{2};
  SecretDataField key_value_{3};
};

class JwtEcdsaKeyFormatTP : public Message<JwtEcdsaKeyFormatTP> {
 public:
  JwtEcdsaKeyFormatTP() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  JwtEcdsaAlgorithmEnum algorithm() const { return algorithm_.value(); }
  void set_algorithm(JwtEcdsaAlgorithmEnum algorithm) {
    algorithm_.set_value(algorithm);
  }

  std::array<const Field*, 2> GetFields() const {
    return {&version_, &algorithm_};
  }

 private:
  Uint32Field version_{1};
  EnumField<JwtEcdsaAlgorithmEnum> algorithm_{2, &JwtEcdsaAlgorithmValid};
};

using JwtEcdsaProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, JwtEcdsaParameters>;
using JwtEcdsaProtoParametersSerializerImpl =
    ParametersSerializerImpl<JwtEcdsaParameters, ProtoParametersSerialization>;
using JwtEcdsaProtoPublicKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, JwtEcdsaPublicKey>;
using JwtEcdsaProtoPublicKeySerializerImpl =
    KeySerializerImpl<JwtEcdsaPublicKey, ProtoKeySerialization>;
using JwtEcdsaProtoPrivateKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, JwtEcdsaPrivateKey>;
using JwtEcdsaProtoPrivateKeySerializerImpl =
    KeySerializerImpl<JwtEcdsaPrivateKey, ProtoKeySerialization>;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey";
const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey";

absl::StatusOr<JwtEcdsaParameters::KidStrategy> ToKidStrategy(
    OutputPrefixTypeEnum output_prefix_type, bool has_custom_kid) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kRaw:
      if (has_custom_kid) {
        return JwtEcdsaParameters::KidStrategy::kCustom;
      }
      return JwtEcdsaParameters::KidStrategy::kIgnored;
    case OutputPrefixTypeEnum::kTink:
      return JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId;
    default:
      return absl::InvalidArgumentError(
          "Invalid OutputPrefixType for JwtEcdsaKeyFormat.");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    JwtEcdsaParameters::KidStrategy kid_strategy) {
  switch (kid_strategy) {
    case JwtEcdsaParameters::KidStrategy::kCustom:
      return OutputPrefixTypeEnum::kRaw;
    case JwtEcdsaParameters::KidStrategy::kIgnored:
      return OutputPrefixTypeEnum::kRaw;
    case JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine JwtEcdsaParameters::KidStrategy.");
  }
}

absl::StatusOr<JwtEcdsaParameters::Algorithm> FromProtoAlgorithm(
    JwtEcdsaAlgorithmEnum algorithm) {
  switch (algorithm) {
    case JwtEcdsaAlgorithmEnum::kEs256:
      return JwtEcdsaParameters::Algorithm::kEs256;
    case JwtEcdsaAlgorithmEnum::kEs384:
      return JwtEcdsaParameters::Algorithm::kEs384;
    case JwtEcdsaAlgorithmEnum::kEs512:
      return JwtEcdsaParameters::Algorithm::kEs512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine JwtEcdsaAlgorithm.");
  }
}

absl::StatusOr<JwtEcdsaAlgorithmEnum> ToProtoAlgorithm(
    JwtEcdsaParameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtEcdsaParameters::Algorithm::kEs256:
      return JwtEcdsaAlgorithmEnum::kEs256;
    case JwtEcdsaParameters::Algorithm::kEs384:
      return JwtEcdsaAlgorithmEnum::kEs384;
    case JwtEcdsaParameters::Algorithm::kEs512:
      return JwtEcdsaAlgorithmEnum::kEs512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine JwtEcdsaParameters::Algorithm");
  }
}

absl::StatusOr<JwtEcdsaParameters> ToParameters(
    OutputPrefixTypeEnum output_prefix_type,
    JwtEcdsaAlgorithmEnum proto_algorithm, bool has_custom_kid) {
  absl::StatusOr<JwtEcdsaParameters::KidStrategy> kid_strategy =
      ToKidStrategy(output_prefix_type, has_custom_kid);
  if (!kid_strategy.ok()) {
    return kid_strategy.status();
  }
  absl::StatusOr<JwtEcdsaParameters::Algorithm> algorithm =
      FromProtoAlgorithm(proto_algorithm);
  if (!algorithm.ok()) {
    return algorithm.status();
  }
  return JwtEcdsaParameters::Create(*kid_strategy, *algorithm);
}

absl::StatusOr<int> GetEncodingLength(JwtEcdsaParameters::Algorithm algorithm) {
  // We currently encode with one extra 0-byte at the beginning, to make sure
  // that parsing is correct. See also b/264525021.
  switch (algorithm) {
    case JwtEcdsaParameters::Algorithm::kEs256:
      return 33;
    case JwtEcdsaParameters::Algorithm::kEs384:
      return 49;
    case JwtEcdsaParameters::Algorithm::kEs512:
      return 67;
    default:
      return absl::InvalidArgumentError(
          "Unable to determine JwtEcdsaParameters::Algorithm.");
  }
}

absl::StatusOr<JwtEcdsaPublicKey> ToPublicKey(
    const JwtEcdsaParameters& parameters,
    const JwtEcdsaPublicKeyTP& proto_public_key,
    absl::optional<int> id_requirement) {
  EcPoint public_point = EcPoint(BigInteger(proto_public_key.x()),
                                 BigInteger(proto_public_key.y()));
  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(parameters)
                                           .SetPublicPoint(public_point);
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(*id_requirement);
  }
  if (proto_public_key.has_custom_kid()) {
    builder.SetCustomKid(proto_public_key.custom_kid().value());
  }
  return builder.Build(GetPartialKeyAccess());
}

absl::StatusOr<JwtEcdsaPublicKeyTP> ToProtoPublicKey(
    const JwtEcdsaPublicKey& public_key) {
  absl::StatusOr<JwtEcdsaAlgorithmEnum> proto_algorithm =
      ToProtoAlgorithm(public_key.GetParameters().GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  absl::StatusOr<int> enc_length =
      GetEncodingLength(public_key.GetParameters().GetAlgorithm());
  if (!enc_length.ok()) {
    return enc_length.status();
  }

  absl::StatusOr<std::string> x = GetValueOfFixedLength(
      public_key.GetPublicPoint(GetPartialKeyAccess()).GetX().GetValue(),
      *enc_length);
  if (!x.ok()) {
    return x.status();
  }

  absl::StatusOr<std::string> y = GetValueOfFixedLength(
      public_key.GetPublicPoint(GetPartialKeyAccess()).GetY().GetValue(),
      *enc_length);
  if (!y.ok()) {
    return y.status();
  }

  JwtEcdsaPublicKeyTP proto_public_key;
  proto_public_key.set_version(0);
  proto_public_key.set_algorithm(*proto_algorithm);
  proto_public_key.set_x(*x);
  proto_public_key.set_y(*y);
  if (public_key.GetParameters().GetKidStrategy() ==
      JwtEcdsaParameters::KidStrategy::kCustom) {
    proto_public_key.mutable_custom_kid()->set_value(*public_key.GetKid());
  }

  return proto_public_key;
}

absl::StatusOr<JwtEcdsaParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtEcdsaParameters.");
  }

  JwtEcdsaKeyFormatTP proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError(
        "Failed to parse JwtEcdsaKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtEcdsaParameters failed: only version 0 is accepted.");
  }

  return ToParameters(key_template.output_prefix_type(),
                      proto_key_format.algorithm(), /*has_custom_kid=*/false);
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const JwtEcdsaParameters& parameters) {
  if (parameters.GetKidStrategy() == JwtEcdsaParameters::KidStrategy::kCustom) {
    return absl::InvalidArgumentError(
        "Unable to serialize JwtEcdsaParameters::KidStrategy::kCustom.");
  }
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  absl::StatusOr<JwtEcdsaAlgorithmEnum> proto_algorithm =
      ToProtoAlgorithm(parameters.GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  JwtEcdsaKeyFormatTP format;
  format.set_version(0);
  format.set_algorithm(*proto_algorithm);

  return ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, format.SerializeAsString());
}

absl::StatusOr<JwtEcdsaPublicKey> ParsePublicKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtEcdsaPublicKey.");
  }

  JwtEcdsaPublicKeyTP proto_public_key;
  if (!proto_public_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(
              InsecureSecretKeyAccess::Get()))) {
    return absl::InvalidArgumentError(
        "Failed to parse JwtEcdsaPublicKey proto");
  }
  if (proto_public_key.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtEcdsaPublicKey failed: only version 0 is accepted.");
  }

  absl::StatusOr<JwtEcdsaParameters> parameters = ToParameters(
      serialization.GetOutputPrefixTypeEnum(), proto_public_key.algorithm(),
      proto_public_key.has_custom_kid());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return ToPublicKey(*parameters, proto_public_key,
                     serialization.IdRequirement());
}

absl::StatusOr<ProtoKeySerialization> SerializePublicKey(
    const JwtEcdsaPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<JwtEcdsaPublicKeyTP> proto_public_key = ToProtoPublicKey(key);
  if (!proto_public_key.ok()) {
    return proto_public_key.status();
  }

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  return ProtoKeySerialization::Create(
      kPublicTypeUrl,
      RestrictedData(proto_public_key->SerializeAsSecretData(),
                     InsecureSecretKeyAccess::Get()),
      KeyMaterialTypeEnum::kAsymmetricPublic, *output_prefix_type,
      key.GetIdRequirement());
}

absl::StatusOr<JwtEcdsaPrivateKey> ParsePrivateKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtEcdsaPrivateKey.");
  }

  JwtEcdsaPrivateKeyTP proto_private_key;
  if (!proto_private_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError(
        "Failed to parse JwtEcdsaPrivateKey proto");
  }
  if (proto_private_key.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtEcdsaPrivateKey failed: only version 0 is accepted.");
  }

  absl::StatusOr<JwtEcdsaParameters> parameters =
      ToParameters(serialization.GetOutputPrefixTypeEnum(),
                   proto_private_key.public_key().algorithm(),
                   proto_private_key.public_key().has_custom_kid());
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      ToPublicKey(*parameters, proto_private_key.public_key(),
                  serialization.IdRequirement());
  if (!public_key.ok()) {
    return public_key.status();
  }

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(proto_private_key.key_value(), *token);
  return JwtEcdsaPrivateKey::Create(*public_key, private_key_value,
                                    GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializePrivateKey(
    const JwtEcdsaPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  absl::StatusOr<JwtEcdsaPublicKeyTP> proto_public_key =
      ToProtoPublicKey(key.GetPublicKey());
  if (!proto_public_key.ok()) {
    return proto_public_key.status();
  }

  absl::StatusOr<RestrictedBigInteger> restricted_input =
      key.GetPrivateKeyValue(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  absl::StatusOr<int> enc_length =
      GetEncodingLength(key.GetPublicKey().GetParameters().GetAlgorithm());
  if (!enc_length.ok()) {
    return enc_length.status();
  }

  JwtEcdsaPrivateKeyTP proto_private_key;
  proto_private_key.set_version(0);
  *proto_private_key.mutable_public_key() = *std::move(proto_public_key);
  proto_private_key.set_key_value(
      *GetSecretValueOfFixedLength(*restricted_input, *enc_length, *token));

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return ProtoKeySerialization::Create(
      kPrivateTypeUrl,
      RestrictedData(proto_private_key.SerializeAsSecretData(),
                     InsecureSecretKeyAccess::Get()),
      KeyMaterialTypeEnum::kAsymmetricPrivate, *output_prefix_type,
      key.GetIdRequirement());
}

JwtEcdsaProtoParametersParserImpl& JwtEcdsaProtoParametersParser() {
  static auto* parser =
      new JwtEcdsaProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return *parser;
}

JwtEcdsaProtoParametersSerializerImpl& JwtEcdsaProtoParametersSerializer() {
  static auto* serializer = new JwtEcdsaProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return *serializer;
}

JwtEcdsaProtoPublicKeyParserImpl& JwtEcdsaProtoPublicKeyParser() {
  static auto* parser =
      new JwtEcdsaProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return *parser;
}

JwtEcdsaProtoPublicKeySerializerImpl& JwtEcdsaProtoPublicKeySerializer() {
  static auto* serializer =
      new JwtEcdsaProtoPublicKeySerializerImpl(SerializePublicKey);
  return *serializer;
}

JwtEcdsaProtoPrivateKeyParserImpl& JwtEcdsaProtoPrivateKeyParser() {
  static auto* parser =
      new JwtEcdsaProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return *parser;
}

JwtEcdsaProtoPrivateKeySerializerImpl& JwtEcdsaProtoPrivateKeySerializer() {
  static auto* serializer =
      new JwtEcdsaProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return *serializer;
}

}  // namespace

absl::Status RegisterJwtEcdsaProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  if (absl::Status status =
          registry.RegisterParametersParser(&JwtEcdsaProtoParametersParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = registry.RegisterParametersSerializer(
          &JwtEcdsaProtoParametersSerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          registry.RegisterKeyParser(&JwtEcdsaProtoPublicKeyParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          registry.RegisterKeySerializer(&JwtEcdsaProtoPublicKeySerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          registry.RegisterKeyParser(&JwtEcdsaProtoPrivateKeyParser());
      !status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(&JwtEcdsaProtoPrivateKeySerializer());
}

absl::Status RegisterJwtEcdsaProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  if (absl::Status status =
          builder.RegisterParametersParser(&JwtEcdsaProtoParametersParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = builder.RegisterParametersSerializer(
          &JwtEcdsaProtoParametersSerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          builder.RegisterKeyParser(&JwtEcdsaProtoPublicKeyParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          builder.RegisterKeySerializer(&JwtEcdsaProtoPublicKeySerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          builder.RegisterKeyParser(&JwtEcdsaProtoPrivateKeyParser());
      !status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(&JwtEcdsaProtoPrivateKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
