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

#include "tink/signature/internal/ml_dsa_proto_serialization_impl.h"

#include <array>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/nullability.h"
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
#include "tink/internal/proto_parser_secret_data_field.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/util/secret_data.h"

ABSL_POINTERS_DEFAULT_NONNULL

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

bool MlDsaInstanceEnumValid(int c) { return c >= 0 && c <= 2; }

enum class MlDsaInstanceEnum : uint32_t {
  kUnknownInstance = 0,
  kMlDsa65,
  kMlDsa87,
};

class MlDsaParamsTP final : public Message {
 public:
  MlDsaParamsTP() = default;

  MlDsaInstanceEnum ml_dsa_instance() const { return ml_dsa_instance_.value(); }
  void set_ml_dsa_instance(MlDsaInstanceEnum value) {
    ml_dsa_instance_.set_value(value);
  }

 private:
  size_t num_fields() const override { return 1; }
  const Field* field(int i) const override {
    return std::array<const Field*, 1>{&ml_dsa_instance_}[i];
  }

  EnumField<MlDsaInstanceEnum> ml_dsa_instance_{1, &MlDsaInstanceEnumValid};
};

class MlDsaKeyFormatTP final : public Message {
 public:
  MlDsaKeyFormatTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const MlDsaParamsTP& params() const { return params_.value(); }
  MlDsaParamsTP* mutable_params() { return params_.mutable_value(); }

  // This is OK because this class doesn't contain secret data.
  using Message::SerializeAsString;

 private:
  size_t num_fields() const override { return 2; }
  const Field* field(int i) const override {
    return std::array<const Field*, 2>{&version_, &params_}[i];
  }

  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  MessageField<MlDsaParamsTP> params_{2};
};

class MlDsaPublicKeyTP final : public Message {
 public:
  MlDsaPublicKeyTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const std::string& key_value() const { return key_value_.value(); }
  void set_key_value(absl::string_view value) { key_value_.set_value(value); }

  const MlDsaParamsTP& params() const { return params_.value(); }
  MlDsaParamsTP* mutable_params() { return params_.mutable_value(); }

 private:
  size_t num_fields() const override { return 3; }
  const Field* field(int i) const override {
    return std::array<const Field*, 3>{&version_, &key_value_, &params_}[i];
  }

  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  BytesField key_value_{2};
  MessageField<MlDsaParamsTP> params_{3};
};

class MlDsaPrivateKeyTP final : public Message {
 public:
  MlDsaPrivateKeyTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(absl::string_view value) {
    *key_value_.mutable_value() = util::SecretDataFromStringView(value);
  }

  const MlDsaPublicKeyTP& public_key() const { return public_key_.value(); }
  MlDsaPublicKeyTP* mutable_public_key() { return public_key_.mutable_value(); }

 private:
  size_t num_fields() const override { return 3; }
  const Field* field(int i) const override {
    return std::array<const Field*, 3>{&version_, &key_value_, &public_key_}[i];
  }

  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  SecretDataField key_value_{2};
  MessageField<MlDsaPublicKeyTP> public_key_{3};
};

using MlDsaProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, MlDsaParameters>;
using MlDsaProtoParametersSerializerImpl =
    ParametersSerializerImpl<MlDsaParameters, ProtoParametersSerialization>;
using MlDsaProtoPublicKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, MlDsaPublicKey>;
using MlDsaProtoPublicKeySerializerImpl =
    KeySerializerImpl<MlDsaPublicKey, ProtoKeySerialization>;
using MlDsaProtoPrivateKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, MlDsaPrivateKey>;
using MlDsaProtoPrivateKeySerializerImpl =
    KeySerializerImpl<MlDsaPrivateKey, ProtoKeySerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.MlDsaPublicKey";

absl::StatusOr<MlDsaParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kRaw:
      return MlDsaParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return MlDsaParameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine MlDsaParameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    MlDsaParameters::Variant variant) {
  switch (variant) {
    case MlDsaParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case MlDsaParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

absl::StatusOr<MlDsaParameters::Instance> ToInstance(
    MlDsaInstanceEnum proto_instance) {
  switch (proto_instance) {
    case MlDsaInstanceEnum::kMlDsa65:
      return MlDsaParameters::Instance::kMlDsa65;
    case MlDsaInstanceEnum::kMlDsa87:
      return MlDsaParameters::Instance::kMlDsa87;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine MlDsaParameters::Instance");
  }
}

absl::StatusOr<MlDsaInstanceEnum> ToProtoInstance(
    MlDsaParameters::Instance instance) {
  switch (instance) {
    case MlDsaParameters::Instance::kMlDsa65:
      return MlDsaInstanceEnum::kMlDsa65;
    case MlDsaParameters::Instance::kMlDsa87:
      return MlDsaInstanceEnum::kMlDsa87;
    default:
      return absl::InvalidArgumentError("Could not determine MlDsaInstance");
  }
}

absl::StatusOr<MlDsaParameters> ToParameters(
    OutputPrefixTypeEnum output_prefix_type, const MlDsaParamsTP& params) {
  absl::StatusOr<MlDsaParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<MlDsaParameters::Instance> instance =
      ToInstance(params.ml_dsa_instance());
  if (!instance.ok()) {
    return instance.status();
  }

  return MlDsaParameters::Create(*instance, *variant);
}

absl::StatusOr<MlDsaParamsTP> FromParameters(
    const MlDsaParameters& parameters) {
  /* Only ML-DSA-65 and ML-DSA-87 are currently supported*/
  absl::StatusOr<MlDsaInstanceEnum> instance =
      ToProtoInstance(parameters.GetInstance());
  if (!instance.ok()) {
    return instance.status();
  }
  MlDsaParamsTP params;
  params.set_ml_dsa_instance(*instance);
  return params;
}

absl::StatusOr<MlDsaParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing MlDsaParameters.");
  }

  MlDsaKeyFormatTP proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError("Failed to parse MlDsaKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  return ToParameters(key_template.output_prefix_type(),
                      proto_key_format.params());
}

absl::StatusOr<MlDsaPublicKey> ParsePublicKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing MlDsaPublicKey.");
  }

  MlDsaPublicKeyTP proto_key;
  if (!proto_key.ParseFromString(serialization.SerializedKeyProto().GetSecret(
          InsecureSecretKeyAccess::Get()))) {
    return absl::InvalidArgumentError("Failed to parse MlDsaPublicKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<MlDsaParameters> parameters =
      ToParameters(serialization.GetOutputPrefixTypeEnum(), proto_key.params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return MlDsaPublicKey::Create(*parameters, proto_key.key_value(),
                                serialization.IdRequirement(),
                                GetPartialKeyAccess());
}

absl::StatusOr<MlDsaPrivateKey> ParsePrivateKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing MlDsaPrivateKey.");
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  MlDsaPrivateKeyTP proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse MlDsaPrivateKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<MlDsaParameters> parameters = ToParameters(
      serialization.GetOutputPrefixTypeEnum(), proto_key.public_key().params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
      *parameters, proto_key.public_key().key_value(),
      serialization.IdRequirement(), GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return MlDsaPrivateKey::Create(*public_key,
                                 RestrictedData(proto_key.key_value(), *token),
                                 GetPartialKeyAccess());
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const MlDsaParameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<MlDsaParamsTP> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }
  MlDsaKeyFormatTP proto_key_format;
  *proto_key_format.mutable_params() = *params;
  proto_key_format.set_version(0);

  std::string serialized_proto = proto_key_format.SerializeAsString();
  return ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, serialized_proto);
}

absl::StatusOr<ProtoKeySerialization> SerializePublicKey(
    const MlDsaPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<MlDsaParamsTP> params = FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  MlDsaPublicKeyTP proto_key;
  proto_key.set_version(0);
  *proto_key.mutable_params() = *params;
  proto_key.set_key_value(key.GetPublicKeyBytes(GetPartialKeyAccess()));

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output = RestrictedData(
      proto_key.SerializeAsSecretData(), InsecureSecretKeyAccess::Get());
  return ProtoKeySerialization::Create(
      kPublicTypeUrl, std::move(restricted_output),
      KeyMaterialTypeEnum::kAsymmetricPublic, *output_prefix_type,
      key.GetIdRequirement());
}

absl::StatusOr<ProtoKeySerialization> SerializePrivateSeed(
    const MlDsaPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetPrivateSeedBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  absl::StatusOr<MlDsaParamsTP> params =
      FromParameters(key.GetPublicKey().GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  MlDsaPrivateKeyTP proto_private_key;
  proto_private_key.set_version(0);
  proto_private_key.mutable_public_key()->set_version(0);
  *proto_private_key.mutable_public_key()->mutable_params() = *params;
  proto_private_key.mutable_public_key()->set_key_value(
      key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess()));
  proto_private_key.set_key_value(restricted_input->GetSecret(*token));

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  SecretData serialized_proto = proto_private_key.SerializeAsSecretData();
  return ProtoKeySerialization::Create(
      kPrivateTypeUrl, RestrictedData(std::move(serialized_proto), *token),
      KeyMaterialTypeEnum::kAsymmetricPrivate, *output_prefix_type,
      key.GetIdRequirement());
}

MlDsaProtoParametersParserImpl& MlDsaProtoParametersParser() {
  static auto parser =
      new MlDsaProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return *parser;
}

MlDsaProtoParametersSerializerImpl& MlDsaProtoParametersSerializer() {
  static auto serializer = new MlDsaProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return *serializer;
}

MlDsaProtoPublicKeyParserImpl& MlDsaProtoPublicKeyParser() {
  static auto* parser =
      new MlDsaProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return *parser;
}

MlDsaProtoPublicKeySerializerImpl& MlDsaProtoPublicKeySerializer() {
  static auto* serializer =
      new MlDsaProtoPublicKeySerializerImpl(SerializePublicKey);
  return *serializer;
}

MlDsaProtoPrivateKeyParserImpl& MlDsaProtoPrivateKeyParser() {
  static auto* parser =
      new MlDsaProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return *parser;
}

MlDsaProtoPrivateKeySerializerImpl& MlDsaProtoPrivateKeySerializer() {
  static auto* serializer =
      new MlDsaProtoPrivateKeySerializerImpl(SerializePrivateSeed);
  return *serializer;
}

}  // namespace

absl::Status RegisterMlDsaProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  if (absl::Status status =
          registry.RegisterParametersParser(&MlDsaProtoParametersParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = registry.RegisterParametersSerializer(
          &MlDsaProtoParametersSerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          registry.RegisterKeyParser(&MlDsaProtoPublicKeyParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          registry.RegisterKeySerializer(&MlDsaProtoPublicKeySerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          registry.RegisterKeyParser(&MlDsaProtoPrivateKeyParser());
      !status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(&MlDsaProtoPrivateKeySerializer());
}

absl::Status RegisterMlDsaProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  if (absl::Status status =
          builder.RegisterParametersParser(&MlDsaProtoParametersParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = builder.RegisterParametersSerializer(
          &MlDsaProtoParametersSerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          builder.RegisterKeyParser(&MlDsaProtoPublicKeyParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          builder.RegisterKeySerializer(&MlDsaProtoPublicKeySerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          builder.RegisterKeyParser(&MlDsaProtoPrivateKeyParser());
      !status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(&MlDsaProtoPrivateKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
