// Copyright 2026 Google LLC
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

#include "tink/jwt/internal/jwt_ml_dsa_proto_serialization_impl.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
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
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/jwt/jwt_ml_dsa_private_key.h"
#include "tink/jwt/jwt_ml_dsa_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
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
using ::crypto::tink::internal::proto_parsing::Uint32Field;

inline bool JwtMlDsaAlgorithmTP_IsValid(int value) {
  switch (value) {
    case 0:  // kMlDsaUnknown
    case 1:  // kMlDsa44
    case 2:  // kMlDsa65
    case 3:  // kMlDsa87
      return true;
    default:
      return false;
  }
}

enum class JwtMlDsaAlgorithmTP : int {
  kMlDsaUnknown = 0,
  kMlDsa44 = 1,
  kMlDsa65 = 2,
  kMlDsa87 = 3,
};

class JwtMlDsaKeyFormatTP : public Message {
 public:
  JwtMlDsaKeyFormatTP() = default;
  using Message::SerializeAsString;

  JwtMlDsaKeyFormatTP(JwtMlDsaKeyFormatTP&&) = default;
  JwtMlDsaKeyFormatTP& operator=(JwtMlDsaKeyFormatTP&&) = default;
  JwtMlDsaKeyFormatTP(const JwtMlDsaKeyFormatTP&) = default;
  JwtMlDsaKeyFormatTP& operator=(const JwtMlDsaKeyFormatTP&) = default;

  void clear_version() { version_.Clear(); }
  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  void clear_algorithm() { algorithm_.Clear(); }
  JwtMlDsaAlgorithmTP algorithm() const { return algorithm_.value(); }
  void set_algorithm(JwtMlDsaAlgorithmTP value) { algorithm_.set_value(value); }

 private:
  size_t num_fields() const override { return 2; }
  const Field* field(int i) const override {
    return std::array<const Field*, 2>{&version_, &algorithm_}[i];
  }

  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  EnumField<JwtMlDsaAlgorithmTP> algorithm_{
      2, &JwtMlDsaAlgorithmTP_IsValid, {}, ProtoFieldOptions::kImplicit};
};

class JwtMlDsaPublicKeyTP : public Message {
 public:
  class CustomKidTP : public Message {
   public:
    CustomKidTP() = default;

    CustomKidTP(CustomKidTP&&) = default;
    CustomKidTP& operator=(CustomKidTP&&) = default;
    CustomKidTP(const CustomKidTP&) = default;
    CustomKidTP& operator=(const CustomKidTP&) = default;

    void clear_value() { value_.Clear(); }
    std::string* mutable_value() { return value_.mutable_value(); }
    const std::string& value() const { return value_.value(); }
    void set_value(absl::string_view value) { value_.set_value(value); }

   private:
    size_t num_fields() const override { return 1; }
    const Field* field(int i) const override {
      return std::array<const Field*, 1>{&value_}[i];
    }

    BytesField value_{1, ProtoFieldOptions::kImplicit};
  };
  JwtMlDsaPublicKeyTP() = default;

  JwtMlDsaPublicKeyTP(JwtMlDsaPublicKeyTP&&) = default;
  JwtMlDsaPublicKeyTP& operator=(JwtMlDsaPublicKeyTP&&) = default;
  JwtMlDsaPublicKeyTP(const JwtMlDsaPublicKeyTP&) = default;
  JwtMlDsaPublicKeyTP& operator=(const JwtMlDsaPublicKeyTP&) = default;

  void clear_version() { version_.Clear(); }
  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  void clear_algorithm() { algorithm_.Clear(); }
  JwtMlDsaAlgorithmTP algorithm() const { return algorithm_.value(); }
  void set_algorithm(JwtMlDsaAlgorithmTP value) { algorithm_.set_value(value); }

  void clear_key_value() { key_value_.Clear(); }
  std::string* mutable_key_value() { return key_value_.mutable_value(); }
  const std::string& key_value() const { return key_value_.value(); }
  void set_key_value(absl::string_view value) { key_value_.set_value(value); }

  bool has_custom_kid() const { return custom_kid_.has_value(); }
  void clear_custom_kid() { custom_kid_.Clear(); }
  JwtMlDsaPublicKeyTP::CustomKidTP* mutable_custom_kid() {
    return custom_kid_.mutable_value();
  }
  const JwtMlDsaPublicKeyTP::CustomKidTP& custom_kid() const {
    return custom_kid_.value();
  }

 private:
  size_t num_fields() const override { return 4; }
  const Field* field(int i) const override {
    return std::array<const Field*, 4>{&version_, &algorithm_, &key_value_,
                                       &custom_kid_}[i];
  }

  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  EnumField<JwtMlDsaAlgorithmTP> algorithm_{
      2, &JwtMlDsaAlgorithmTP_IsValid, {}, ProtoFieldOptions::kImplicit};
  BytesField key_value_{3, ProtoFieldOptions::kImplicit};
  MessageField<JwtMlDsaPublicKeyTP::CustomKidTP> custom_kid_{
      4, ProtoFieldOptions::kExplicit};
};

class JwtMlDsaPrivateKeyTP : public Message {
 public:
  JwtMlDsaPrivateKeyTP() = default;

  JwtMlDsaPrivateKeyTP(JwtMlDsaPrivateKeyTP&&) = default;
  JwtMlDsaPrivateKeyTP& operator=(JwtMlDsaPrivateKeyTP&&) = default;
  JwtMlDsaPrivateKeyTP(const JwtMlDsaPrivateKeyTP&) = default;
  JwtMlDsaPrivateKeyTP& operator=(const JwtMlDsaPrivateKeyTP&) = default;

  void clear_version() { version_.Clear(); }
  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  void clear_key_value() { key_value_.Clear(); }
  std::string* mutable_key_value() { return key_value_.mutable_value(); }
  const std::string& key_value() const { return key_value_.value(); }
  void set_key_value(absl::string_view value) { key_value_.set_value(value); }

  bool has_public_key() const { return public_key_.has_value(); }
  void clear_public_key() { public_key_.Clear(); }
  JwtMlDsaPublicKeyTP* mutable_public_key() {
    return public_key_.mutable_value();
  }
  const JwtMlDsaPublicKeyTP& public_key() const { return public_key_.value(); }

 private:
  size_t num_fields() const override { return 3; }
  const Field* field(int i) const override {
    return std::array<const Field*, 3>{&version_, &key_value_, &public_key_}[i];
  }

  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  BytesField key_value_{2, ProtoFieldOptions::kImplicit};
  MessageField<JwtMlDsaPublicKeyTP> public_key_{3,
                                                ProtoFieldOptions::kExplicit};
};

using JwtMlDsaProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, JwtMlDsaParameters>;
using JwtMlDsaProtoParametersSerializerImpl =
    ParametersSerializerImpl<JwtMlDsaParameters, ProtoParametersSerialization>;
using JwtMlDsaProtoPublicKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, JwtMlDsaPublicKey>;
using JwtMlDsaProtoPublicKeySerializerImpl =
    KeySerializerImpl<JwtMlDsaPublicKey, ProtoKeySerialization>;
using JwtMlDsaProtoPrivateKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, JwtMlDsaPrivateKey>;
using JwtMlDsaProtoPrivateKeySerializerImpl =
    KeySerializerImpl<JwtMlDsaPrivateKey, ProtoKeySerialization>;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtMlDsaPublicKey";
const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey";

absl::StatusOr<JwtMlDsaParameters::KidStrategy> ToKidStrategy(
    OutputPrefixTypeTP output_prefix_type, bool has_custom_kid) {
  switch (output_prefix_type) {
    case OutputPrefixTypeTP::kRaw:
      if (has_custom_kid) {
        return JwtMlDsaParameters::KidStrategy::kCustom;
      }
      return JwtMlDsaParameters::KidStrategy::kIgnored;
    case OutputPrefixTypeTP::kTink:
      return JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId;
    default:
      return absl::InvalidArgumentError(
          "Invalid OutputPrefixType for JwtMlDsaKeyFormat.");
  }
}

absl::StatusOr<OutputPrefixTypeTP> ToOutputPrefixType(
    JwtMlDsaParameters::KidStrategy kid_strategy) {
  switch (kid_strategy) {
    case JwtMlDsaParameters::KidStrategy::kCustom:
      return OutputPrefixTypeTP::kRaw;
    case JwtMlDsaParameters::KidStrategy::kIgnored:
      return OutputPrefixTypeTP::kRaw;
    case JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId:
      return OutputPrefixTypeTP::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine JwtMlDsaParameters::KidStrategy.");
  }
}

absl::StatusOr<JwtMlDsaParameters::Algorithm> FromProtoAlgorithm(
    JwtMlDsaAlgorithmTP algorithm) {
  switch (algorithm) {
    case JwtMlDsaAlgorithmTP::kMlDsa44:
      return JwtMlDsaParameters::Algorithm::kMlDsa44;
    case JwtMlDsaAlgorithmTP::kMlDsa65:
      return JwtMlDsaParameters::Algorithm::kMlDsa65;
    case JwtMlDsaAlgorithmTP::kMlDsa87:
      return JwtMlDsaParameters::Algorithm::kMlDsa87;
    default:
      return absl::InvalidArgumentError(
          "Could not determine JwtMlDsaAlgorithm.");
  }
}

absl::StatusOr<JwtMlDsaAlgorithmTP> ToProtoAlgorithm(
    JwtMlDsaParameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtMlDsaParameters::Algorithm::kMlDsa44:
      return JwtMlDsaAlgorithmTP::kMlDsa44;
    case JwtMlDsaParameters::Algorithm::kMlDsa65:
      return JwtMlDsaAlgorithmTP::kMlDsa65;
    case JwtMlDsaParameters::Algorithm::kMlDsa87:
      return JwtMlDsaAlgorithmTP::kMlDsa87;
    default:
      return absl::InvalidArgumentError(
          "Could not determine JwtMlDsaParameters::Algorithm");
  }
}

absl::StatusOr<JwtMlDsaParameters> ToParameters(
    OutputPrefixTypeTP output_prefix_type, JwtMlDsaAlgorithmTP proto_algorithm,
    bool has_custom_kid) {
  absl::StatusOr<JwtMlDsaParameters::KidStrategy> kid_strategy =
      ToKidStrategy(output_prefix_type, has_custom_kid);
  if (!kid_strategy.ok()) {
    return kid_strategy.status();
  }
  absl::StatusOr<JwtMlDsaParameters::Algorithm> algorithm =
      FromProtoAlgorithm(proto_algorithm);
  if (!algorithm.ok()) {
    return algorithm.status();
  }
  return JwtMlDsaParameters::Create(*kid_strategy, *algorithm);
}

absl::StatusOr<JwtMlDsaPublicKey> ToPublicKey(
    const JwtMlDsaParameters& parameters,
    const JwtMlDsaPublicKeyTP& proto_public_key,
    absl::optional<int> id_requirement) {
  JwtMlDsaPublicKey::Builder builder =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(parameters)
          .SetPublicKeyBytes(proto_public_key.key_value());
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(*id_requirement);
  }
  if (proto_public_key.has_custom_kid()) {
    builder.SetCustomKid(proto_public_key.custom_kid().value());
  }
  return builder.Build(GetPartialKeyAccess());
}

absl::StatusOr<JwtMlDsaPublicKeyTP> ToProtoPublicKey(
    const JwtMlDsaPublicKey& public_key) {
  absl::StatusOr<JwtMlDsaAlgorithmTP> proto_algorithm =
      ToProtoAlgorithm(public_key.GetParameters().GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  JwtMlDsaPublicKeyTP proto_public_key;
  proto_public_key.set_version(0);
  proto_public_key.set_algorithm(*proto_algorithm);
  proto_public_key.set_key_value(
      public_key.GetPublicKeyBytes(GetPartialKeyAccess()));
  if (public_key.GetParameters().GetKidStrategy() ==
      JwtMlDsaParameters::KidStrategy::kCustom) {
    proto_public_key.mutable_custom_kid()->set_value(*public_key.GetKid());
  }

  return proto_public_key;
}

absl::StatusOr<JwtMlDsaParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtMlDsaParameters.");
  }

  JwtMlDsaKeyFormatTP proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError(
        "Failed to parse JwtMlDsaKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtMlDsaParameters failed: only version 0 is accepted.");
  }

  return ToParameters(key_template.output_prefix_type(),
                      proto_key_format.algorithm(), /*has_custom_kid=*/false);
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const JwtMlDsaParameters& parameters) {
  if (parameters.GetKidStrategy() == JwtMlDsaParameters::KidStrategy::kCustom) {
    return absl::InvalidArgumentError(
        "Unable to serialize JwtMlDsaParameters::KidStrategy::kCustom.");
  }
  absl::StatusOr<OutputPrefixTypeTP> output_prefix_type =
      ToOutputPrefixType(parameters.GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  absl::StatusOr<JwtMlDsaAlgorithmTP> proto_algorithm =
      ToProtoAlgorithm(parameters.GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  JwtMlDsaKeyFormatTP format;
  format.set_version(0);
  format.set_algorithm(*proto_algorithm);

  return ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, format.SerializeAsString());
}

absl::StatusOr<JwtMlDsaPublicKey> ParsePublicKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtMlDsaPublicKey.");
  }

  JwtMlDsaPublicKeyTP proto_public_key;
  if (!proto_public_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(
              InsecureSecretKeyAccess::Get()))) {
    return absl::InvalidArgumentError(
        "Failed to parse JwtMlDsaPublicKey proto");
  }
  if (proto_public_key.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtMlDsaPublicKey failed: only version 0 is accepted.");
  }

  absl::StatusOr<JwtMlDsaParameters> parameters = ToParameters(
      serialization.GetOutputPrefixTypeTP(), proto_public_key.algorithm(),
      proto_public_key.has_custom_kid());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return ToPublicKey(*parameters, proto_public_key,
                     serialization.IdRequirement());
}

absl::StatusOr<ProtoKeySerialization> SerializePublicKey(
    const JwtMlDsaPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<JwtMlDsaPublicKeyTP> proto_public_key = ToProtoPublicKey(key);
  if (!proto_public_key.ok()) {
    return proto_public_key.status();
  }

  absl::StatusOr<OutputPrefixTypeTP> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  return ProtoKeySerialization::Create(
      kPublicTypeUrl,
      RestrictedData(proto_public_key->SerializeAsSecretData(),
                     InsecureSecretKeyAccess::Get()),
      KeyMaterialTypeTP::kAsymmetricPublic, *output_prefix_type,
      key.GetIdRequirement());
}

absl::StatusOr<JwtMlDsaPrivateKey> ParsePrivateKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtMlDsaPrivateKey.");
  }

  JwtMlDsaPrivateKeyTP proto_private_key;
  if (!proto_private_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError(
        "Failed to parse JwtMlDsaPrivateKey proto");
  }
  if (proto_private_key.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtMlDsaPrivateKey failed: only version 0 is accepted.");
  }

  absl::StatusOr<JwtMlDsaParameters> parameters =
      ToParameters(serialization.GetOutputPrefixTypeTP(),
                   proto_private_key.public_key().algorithm(),
                   proto_private_key.public_key().has_custom_kid());
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      ToPublicKey(*parameters, proto_private_key.public_key(),
                  serialization.IdRequirement());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return JwtMlDsaPrivateKey::Create(
      *public_key,
      RestrictedData(proto_private_key.key_value(),
                     InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializePrivateKey(
    const JwtMlDsaPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  absl::StatusOr<JwtMlDsaPublicKeyTP> proto_public_key =
      ToProtoPublicKey(key.GetPublicKey());
  if (!proto_public_key.ok()) {
    return proto_public_key.status();
  }

  absl::StatusOr<RestrictedData> restricted_input =
      key.GetPrivateSeedBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  JwtMlDsaPrivateKeyTP proto_private_key;
  proto_private_key.set_version(0);
  *proto_private_key.mutable_public_key() = *std::move(proto_public_key);
  proto_private_key.set_key_value(restricted_input->GetSecret(*token));

  absl::StatusOr<OutputPrefixTypeTP> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return ProtoKeySerialization::Create(
      kPrivateTypeUrl,
      RestrictedData(proto_private_key.SerializeAsSecretData(),
                     InsecureSecretKeyAccess::Get()),
      KeyMaterialTypeTP::kAsymmetricPrivate, *output_prefix_type,
      key.GetIdRequirement());
}

JwtMlDsaProtoParametersParserImpl& JwtMlDsaProtoParametersParser() {
  static auto* parser =
      new JwtMlDsaProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return *parser;
}

JwtMlDsaProtoParametersSerializerImpl& JwtMlDsaProtoParametersSerializer() {
  static auto* serializer = new JwtMlDsaProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return *serializer;
}

JwtMlDsaProtoPublicKeyParserImpl& JwtMlDsaProtoPublicKeyParser() {
  static auto* parser =
      new JwtMlDsaProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return *parser;
}

JwtMlDsaProtoPublicKeySerializerImpl& JwtMlDsaProtoPublicKeySerializer() {
  static auto* serializer =
      new JwtMlDsaProtoPublicKeySerializerImpl(SerializePublicKey);
  return *serializer;
}

JwtMlDsaProtoPrivateKeyParserImpl& JwtMlDsaProtoPrivateKeyParser() {
  static auto* parser =
      new JwtMlDsaProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return *parser;
}

JwtMlDsaProtoPrivateKeySerializerImpl& JwtMlDsaProtoPrivateKeySerializer() {
  static auto* serializer =
      new JwtMlDsaProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return *serializer;
}

}  // namespace

absl::Status RegisterJwtMlDsaProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  if (absl::Status status =
          registry.RegisterParametersParser(&JwtMlDsaProtoParametersParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = registry.RegisterParametersSerializer(
          &JwtMlDsaProtoParametersSerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          registry.RegisterKeyParser(&JwtMlDsaProtoPublicKeyParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          registry.RegisterKeySerializer(&JwtMlDsaProtoPublicKeySerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          registry.RegisterKeyParser(&JwtMlDsaProtoPrivateKeyParser());
      !status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(&JwtMlDsaProtoPrivateKeySerializer());
}

absl::Status RegisterJwtMlDsaProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  if (absl::Status status =
          builder.RegisterParametersParser(&JwtMlDsaProtoParametersParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = builder.RegisterParametersSerializer(
          &JwtMlDsaProtoParametersSerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          builder.RegisterKeyParser(&JwtMlDsaProtoPublicKeyParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          builder.RegisterKeySerializer(&JwtMlDsaProtoPublicKeySerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          builder.RegisterKeyParser(&JwtMlDsaProtoPrivateKeyParser());
      !status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(&JwtMlDsaProtoPrivateKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
