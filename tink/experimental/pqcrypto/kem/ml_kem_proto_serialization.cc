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

#include "tink/experimental/pqcrypto/kem/ml_kem_proto_serialization.h"

#include <array>
#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_public_key.h"
#include "tink/insecure_secret_key_access.h"
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
#include "tink/internal/tink_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::proto_parsing::EnumOwningField;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageOwningField;
using ::crypto::tink::internal::proto_parsing::OwningBytesField;
using ::crypto::tink::internal::proto_parsing::OwningField;
using ::crypto::tink::internal::proto_parsing::SecretDataOwningField;
using ::crypto::tink::internal::proto_parsing::Uint32OwningField;

bool MlKemKeySizeEnumIsValid(int c) { return c >= 0 && c <= 1; }

enum class MlKemKeySizeEnum : uint32_t {
  kUnknown = 0,
  kMlKem768 = 1,
};

class MlKemParamsTP : public Message<MlKemParamsTP> {
 public:
  MlKemParamsTP() = default;
  using Message::SerializeAsString;

  MlKemKeySizeEnum ml_kem_key_size() const { return ml_kem_key_size_.value(); }
  void set_ml_kem_key_size(MlKemKeySizeEnum value) {
    ml_kem_key_size_.set_value(value);
  }

  std::array<const OwningField*, 1> GetFields() const {
    return {&ml_kem_key_size_};
  }

 private:
  EnumOwningField<MlKemKeySizeEnum> ml_kem_key_size_{1,
                                                     &MlKemKeySizeEnumIsValid};
};

class MlKemKeyFormatTP : public Message<MlKemKeyFormatTP> {
 public:
  MlKemKeyFormatTP() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const MlKemParamsTP& params() const { return params_.value(); }
  MlKemParamsTP* mutable_params() { return params_.mutable_value(); }

  std::array<const OwningField*, 2> GetFields() const {
    return {&version_, &params_};
  }

 private:
  Uint32OwningField version_{1};
  MessageOwningField<MlKemParamsTP> params_{2};
};

class MlKemPublicKeyTP : public Message<MlKemPublicKeyTP> {
 public:
  MlKemPublicKeyTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const std::string& key_value() const { return key_value_.value(); }
  std::string* mutable_key_value() { return key_value_.mutable_value(); }

  const MlKemParamsTP& params() const { return params_.value(); }
  MlKemParamsTP* mutable_params() { return params_.mutable_value(); }

  std::array<const OwningField*, 3> GetFields() const {
    return {&version_, &key_value_, &params_};
  }

 private:
  Uint32OwningField version_{1};
  OwningBytesField<std::string> key_value_{2};
  MessageOwningField<MlKemParamsTP> params_{3};
};

class MlKemPrivateKeyTP : public Message<MlKemPrivateKeyTP> {
 public:
  MlKemPrivateKeyTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const SecretData& key_value() const { return key_value_.value(); }
  SecretData* mutable_key_value() { return key_value_.mutable_value(); }

  const MlKemPublicKeyTP& public_key() const { return public_key_.value(); }
  MlKemPublicKeyTP* mutable_public_key() { return public_key_.mutable_value(); }

  std::array<const OwningField*, 3> GetFields() const {
    return {&version_, &key_value_, &public_key_};
  }

 private:
  Uint32OwningField version_{1};
  SecretDataOwningField key_value_{2};
  MessageOwningField<MlKemPublicKeyTP> public_key_{3};
};

using MlKemProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   MlKemParameters>;
using MlKemProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<MlKemParameters,
                                       internal::ProtoParametersSerialization>;
using MlKemProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, MlKemPublicKey>;
using MlKemProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<MlKemPublicKey,
                                internal::ProtoKeySerialization>;
using MlKemProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, MlKemPrivateKey>;
using MlKemProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<MlKemPrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.MlKemPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.MlKemPublicKey";

absl::StatusOr<MlKemParameters::Variant> ToVariant(
    internal::OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case internal::OutputPrefixTypeEnum::kTink:
      return MlKemParameters::Variant::kTink;
    case internal::OutputPrefixTypeEnum::kRaw:
      return absl::InvalidArgumentError(
          "Invalid output prefix type RAW for MlKemParameters");
    default:
      return absl::InvalidArgumentError(
          "Could not determine MlKemParameters::Variant");
  }
}

absl::StatusOr<internal::OutputPrefixTypeEnum> ToOutputPrefixType(
    MlKemParameters::Variant variant) {
  switch (variant) {
    case MlKemParameters::Variant::kTink:
      return internal::OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

absl::StatusOr<int> ToKeySize(MlKemKeySizeEnum key_size) {
  switch (key_size) {
    case MlKemKeySizeEnum::kMlKem768:
      return 768;
    default:
      return absl::InvalidArgumentError(
          "Could not determine MlKemParameters' key size");
  }
}

absl::StatusOr<MlKemKeySizeEnum> ToProtoKeySize(int key_size) {
  switch (key_size) {
    case 768:
      return MlKemKeySizeEnum::kMlKem768;
    default:
      return absl::InvalidArgumentError("Could not determine MlKemKeySize");
  }
}

absl::StatusOr<MlKemParameters> ToParameters(
    internal::OutputPrefixTypeEnum output_prefix_type,
    const MlKemParamsTP& params) {
  absl::StatusOr<MlKemParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<int> key_size = ToKeySize(params.ml_kem_key_size());
  if (!key_size.ok()) {
    return key_size.status();
  }

  return MlKemParameters::Create(*key_size, *variant);
}

absl::StatusOr<MlKemParamsTP> FromParameters(
    const MlKemParameters& parameters) {
  absl::StatusOr<MlKemKeySizeEnum> key_size =
      ToProtoKeySize(parameters.GetKeySize());
  if (!key_size.ok()) {
    return key_size.status();
  }

  MlKemParamsTP params;
  params.set_ml_kem_key_size(*key_size);
  return params;
}

absl::StatusOr<MlKemParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  const internal::KeyTemplateTP& key_template = serialization.GetKeyTemplate();

  if (key_template.type_url() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing MlKemParameters.");
  }

  MlKemKeyFormatTP proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError("Failed to parse MlKemKeyFormat.");
  }
  if (proto_key_format.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }
  return ToParameters(key_template.output_prefix_type(),
                      proto_key_format.params());
}

absl::StatusOr<MlKemPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> /*token*/) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing MlKemPublicKey.");
  }

  MlKemPublicKeyTP proto_key;
  if (!proto_key.ParseFromString(serialization.SerializedKeyProto().GetSecret(
          InsecureSecretKeyAccess::Get()))) {
    return absl::InvalidArgumentError("Failed to parse MlKemPublicKey.");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<MlKemParameters> parameters =
      ToParameters(serialization.GetOutputPrefixTypeEnum(), proto_key.params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return MlKemPublicKey::Create(*parameters, proto_key.key_value(),
                                serialization.IdRequirement(),
                                GetPartialKeyAccess());
}

absl::StatusOr<MlKemPrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing MlKemPrivateKey.");
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  MlKemPrivateKeyTP proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse MlKemPrivateKey.");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<MlKemParameters> parameters = ToParameters(
      serialization.GetOutputPrefixTypeEnum(), proto_key.public_key().params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<MlKemPublicKey> public_key = MlKemPublicKey::Create(
      *parameters, proto_key.public_key().key_value(),
      serialization.IdRequirement(), GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return MlKemPrivateKey::Create(*public_key,
                                 RestrictedData(proto_key.key_value(), *token),
                                 GetPartialKeyAccess());
}

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const MlKemParameters& parameters) {
  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<MlKemParamsTP> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }
  MlKemKeyFormatTP proto_key_format;
  *proto_key_format.mutable_params() = *params;
  proto_key_format.set_version(0);

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type,
      proto_key_format.SerializeAsString());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const MlKemPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<MlKemParamsTP> params = FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  MlKemPublicKeyTP proto_key;
  proto_key.set_version(0);
  *proto_key.mutable_params() = *params;
  *proto_key.mutable_key_value() = key.GetPublicKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl,
      RestrictedData(proto_key.SerializeAsSecretData(),
                     InsecureSecretKeyAccess::Get()),
      internal::KeyMaterialTypeEnum::kAsymmetricPublic, *output_prefix_type,
      key.GetIdRequirement());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePrivateSeed(
    const MlKemPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetPrivateSeedBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  absl::StatusOr<MlKemParamsTP> params =
      FromParameters(key.GetPublicKey().GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  MlKemPrivateKeyTP proto_private_key;
  proto_private_key.set_version(0);
  proto_private_key.mutable_public_key()->set_version(0);
  *proto_private_key.mutable_public_key()->mutable_params() = *params;
  *proto_private_key.mutable_public_key()->mutable_key_value() =
      key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());
  *proto_private_key.mutable_key_value() = restricted_input->Get(*token);

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl,
      RestrictedData(proto_private_key.SerializeAsSecretData(), *token),
      internal::KeyMaterialTypeEnum::kAsymmetricPrivate, *output_prefix_type,
      key.GetIdRequirement());
}

MlKemProtoParametersParserImpl& MlKemProtoParametersParser() {
  static auto parser =
      new MlKemProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return *parser;
}

MlKemProtoParametersSerializerImpl& MlKemProtoParametersSerializer() {
  static auto serializer = new MlKemProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return *serializer;
}

MlKemProtoPublicKeyParserImpl& MlKemProtoPublicKeyParser() {
  static auto* parser =
      new MlKemProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return *parser;
}

MlKemProtoPublicKeySerializerImpl& MlKemProtoPublicKeySerializer() {
  static auto* serializer =
      new MlKemProtoPublicKeySerializerImpl(SerializePublicKey);
  return *serializer;
}

MlKemProtoPrivateKeyParserImpl& MlKemProtoPrivateKeyParser() {
  static auto* parser =
      new MlKemProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return *parser;
}

MlKemProtoPrivateKeySerializerImpl& MlKemProtoPrivateKeySerializer() {
  static auto* serializer =
      new MlKemProtoPrivateKeySerializerImpl(SerializePrivateSeed);
  return *serializer;
}

}  // namespace

absl::Status RegisterMlKemProtoSerialization() {
  absl::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(&MlKemProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(&MlKemProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&MlKemProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeySerializer(&MlKemProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&MlKemProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(&MlKemProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
