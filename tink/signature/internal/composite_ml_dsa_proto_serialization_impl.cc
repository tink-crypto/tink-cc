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

#include "tink/signature/internal/composite_ml_dsa_proto_serialization_impl.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/base/no_destructor.h"
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
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/internal/util.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/composite_ml_dsa_public_key.h"
#include "tink/signature/internal/ecdsa_proto_serialization_impl.h"
#include "tink/signature/internal/ed25519_proto_serialization_impl.h"
#include "tink/signature/internal/ml_dsa_proto_serialization_impl.h"
#include "tink/signature/internal/rsa_ssa_pkcs1_proto_serialization_impl.h"
#include "tink/signature/internal/rsa_ssa_pss_proto_serialization_impl.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/signature_public_key.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::EnumField;
using ::crypto::tink::internal::proto_parsing::Field;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageField;
using ::crypto::tink::internal::proto_parsing::Uint32Field;

absl::StatusOr<SerializationRegistry*> GetSerializationRegistry() {
  static absl::NoDestructor<absl::StatusOr<SerializationRegistry>> registry(
      []() -> absl::StatusOr<SerializationRegistry> {
        SerializationRegistry::Builder builder;
        absl::Status status =
            RegisterMlDsaProtoSerializationWithRegistryBuilder(builder);
        if (!status.ok()) return status;
        status =
            RegisterRsaSsaPkcs1ProtoSerializationWithRegistryBuilder(builder);
        if (!status.ok()) return status;
        status =
            RegisterRsaSsaPssProtoSerializationWithRegistryBuilder(builder);
        if (!status.ok()) return status;
        status = RegisterEcdsaProtoSerializationWithRegistryBuilder(builder);
        if (!status.ok()) return status;
        status = RegisterEd25519ProtoSerializationWithRegistryBuilder(builder);
        if (!status.ok()) return status;
        return std::move(builder).Build();
      }());
  if (!registry->ok()) {
    return registry->status();
  }
  return &registry->value();
}

bool MlDsaInstanceEnumTPValid(int c) { return c >= 0 && c <= 2; }

enum class MlDsaInstanceEnumTP : uint32_t {
  kUnknownInstance = 0,
  kMlDsa65,
  kMlDsa87,
};

bool CompositeMlDsaClassicalAlgorithmEnumTPValid(int c) {
  return c >= 0 && c <= 8;
}

enum class CompositeMlDsaClassicalAlgorithmEnumTP : uint32_t {
  kUnknown = 0,
  kEd25519,
  kEcdsaP256,
  kEcdsaP384,
  kEcdsaP521,
  kRsa3072Pss,
  kRsa4096Pss,
  kRsa3072Pkcs1,
  kRsa4096Pkcs1,
};

class CompositeMlDsaParamsTP final : public Message {
 public:
  CompositeMlDsaParamsTP() = default;

  MlDsaInstanceEnumTP ml_dsa_instance() const {
    return ml_dsa_instance_.value();
  }
  void set_ml_dsa_instance(MlDsaInstanceEnumTP value) {
    ml_dsa_instance_.set_value(value);
  }

  CompositeMlDsaClassicalAlgorithmEnumTP classical_algorithm() const {
    return classical_algorithm_.value();
  }
  void set_classical_algorithm(CompositeMlDsaClassicalAlgorithmEnumTP value) {
    classical_algorithm_.set_value(value);
  }

 private:
  size_t num_fields() const override { return 2; }
  const Field* field(int i) const override {
    return std::array<const Field*, 2>{&ml_dsa_instance_,
                                       &classical_algorithm_}[i];
  }

  EnumField<MlDsaInstanceEnumTP> ml_dsa_instance_{1, &MlDsaInstanceEnumTPValid};
  EnumField<CompositeMlDsaClassicalAlgorithmEnumTP> classical_algorithm_{
      2, &CompositeMlDsaClassicalAlgorithmEnumTPValid};
};

class CompositeMlDsaFormatTP final : public Message {
 public:
  CompositeMlDsaFormatTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const CompositeMlDsaParamsTP& params() const { return params_.value(); }
  CompositeMlDsaParamsTP* mutable_params() { return params_.mutable_value(); }

  // This is OK because this class doesn't contain secret data.
  using Message::SerializeAsString;

 private:
  size_t num_fields() const override { return 2; }
  const Field* field(int i) const override {
    return std::array<const Field*, 2>{&version_, &params_}[i];
  }

  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  MessageField<CompositeMlDsaParamsTP> params_{2};
};

class CompositeMlDsaPublicKeyTP final : public Message {
 public:
  CompositeMlDsaPublicKeyTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const KeyDataTP& ml_dsa_public_key() const {
    return ml_dsa_public_key_.value();
  }
  KeyDataTP* mutable_ml_dsa_public_key() {
    return ml_dsa_public_key_.mutable_value();
  }

  const KeyDataTP& classical_public_key() const {
    return classical_public_key_.value();
  }
  KeyDataTP* mutable_classical_public_key() {
    return classical_public_key_.mutable_value();
  }

  const CompositeMlDsaParamsTP& params() const { return params_.value(); }
  CompositeMlDsaParamsTP* mutable_params() { return params_.mutable_value(); }

 private:
  size_t num_fields() const override { return 4; }
  const Field* field(int i) const override {
    return std::array<const Field*, 4>{&version_, &ml_dsa_public_key_,
                                       &classical_public_key_, &params_}[i];
  }

  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  MessageField<KeyDataTP> ml_dsa_public_key_{2};
  MessageField<KeyDataTP> classical_public_key_{3};
  MessageField<CompositeMlDsaParamsTP> params_{4};
};

using CompositeMlDsaProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization,
                         CompositeMlDsaParameters>;
using CompositeMlDsaProtoParametersSerializerImpl =
    ParametersSerializerImpl<CompositeMlDsaParameters,
                             ProtoParametersSerialization>;
using CompositeMlDsaPublicKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, CompositeMlDsaPublicKey>;
using CompositeMlDsaPublicKeySerializerImpl =
    KeySerializerImpl<CompositeMlDsaPublicKey, ProtoKeySerialization>;

constexpr absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.CompositeMlDsaPrivateKey";
constexpr absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.CompositeMlDsaPublicKey";

absl::StatusOr<CompositeMlDsaParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kRaw:
      return CompositeMlDsaParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return CompositeMlDsaParameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine CompositeMlDsaParameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    CompositeMlDsaParameters::Variant variant) {
  switch (variant) {
    case CompositeMlDsaParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case CompositeMlDsaParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

absl::StatusOr<CompositeMlDsaParameters::MlDsaInstance> ToMlDsaInstance(
    MlDsaInstanceEnumTP proto_instance) {
  switch (proto_instance) {
    case MlDsaInstanceEnumTP::kMlDsa65:
      return CompositeMlDsaParameters::MlDsaInstance::kMlDsa65;
    case MlDsaInstanceEnumTP::kMlDsa87:
      return CompositeMlDsaParameters::MlDsaInstance::kMlDsa87;
    default:
      return absl::InvalidArgumentError(
          "Could not determine CompositeMlDsaParameters::MlDsaInstance");
  }
}

absl::StatusOr<MlDsaInstanceEnumTP> ToProtoMlDsaInstance(
    CompositeMlDsaParameters::MlDsaInstance instance) {
  switch (instance) {
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa65:
      return MlDsaInstanceEnumTP::kMlDsa65;
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa87:
      return MlDsaInstanceEnumTP::kMlDsa87;
    default:
      return absl::InvalidArgumentError(
          "Could not determine CompositeMlDsaParameters::MlDsaInstance");
  }
}

absl::StatusOr<CompositeMlDsaParameters::ClassicalAlgorithm>
ToClassicalAlgorithm(CompositeMlDsaClassicalAlgorithmEnumTP proto_algorithm) {
  switch (proto_algorithm) {
    case CompositeMlDsaClassicalAlgorithmEnumTP::kEd25519:
      return CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519;
    case CompositeMlDsaClassicalAlgorithmEnumTP::kEcdsaP256:
      return CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256;
    case CompositeMlDsaClassicalAlgorithmEnumTP::kEcdsaP384:
      return CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384;
    case CompositeMlDsaClassicalAlgorithmEnumTP::kEcdsaP521:
      return CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521;
    case CompositeMlDsaClassicalAlgorithmEnumTP::kRsa3072Pss:
      return CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss;
    case CompositeMlDsaClassicalAlgorithmEnumTP::kRsa4096Pss:
      return CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss;
    case CompositeMlDsaClassicalAlgorithmEnumTP::kRsa3072Pkcs1:
      return CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1;
    case CompositeMlDsaClassicalAlgorithmEnumTP::kRsa4096Pkcs1:
      return CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1;
    default:
      return absl::InvalidArgumentError(
          "Could not determine CompositeMlDsaParameters::ClassicalAlgorithm");
  }
}

absl::StatusOr<CompositeMlDsaClassicalAlgorithmEnumTP>
ToProtoClassicalAlgorithm(
    CompositeMlDsaParameters::ClassicalAlgorithm algorithm) {
  switch (algorithm) {
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519:
      return CompositeMlDsaClassicalAlgorithmEnumTP::kEd25519;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256:
      return CompositeMlDsaClassicalAlgorithmEnumTP::kEcdsaP256;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384:
      return CompositeMlDsaClassicalAlgorithmEnumTP::kEcdsaP384;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521:
      return CompositeMlDsaClassicalAlgorithmEnumTP::kEcdsaP521;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss:
      return CompositeMlDsaClassicalAlgorithmEnumTP::kRsa3072Pss;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss:
      return CompositeMlDsaClassicalAlgorithmEnumTP::kRsa4096Pss;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1:
      return CompositeMlDsaClassicalAlgorithmEnumTP::kRsa3072Pkcs1;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1:
      return CompositeMlDsaClassicalAlgorithmEnumTP::kRsa4096Pkcs1;
    default:
      return absl::InvalidArgumentError(
          "Could not determine CompositeMlDsaParameters::ClassicalAlgorithm");
  }
}

absl::StatusOr<CompositeMlDsaParameters> ToParameters(
    OutputPrefixTypeEnum output_prefix_type,
    MlDsaInstanceEnumTP ml_dsa_instance_enum,
    CompositeMlDsaClassicalAlgorithmEnumTP classical_algorithm_enum) {
  absl::StatusOr<CompositeMlDsaParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }
  absl::StatusOr<CompositeMlDsaParameters::MlDsaInstance> ml_dsa_instance =
      ToMlDsaInstance(ml_dsa_instance_enum);
  if (!ml_dsa_instance.ok()) {
    return ml_dsa_instance.status();
  }
  absl::StatusOr<CompositeMlDsaParameters::ClassicalAlgorithm>
      classical_algorithm = ToClassicalAlgorithm(classical_algorithm_enum);
  if (!classical_algorithm.ok()) {
    return classical_algorithm.status();
  }
  return CompositeMlDsaParameters::Create(*ml_dsa_instance,
                                          *classical_algorithm, *variant);
}

absl::StatusOr<CompositeMlDsaParamsTP> FromParameters(
    const CompositeMlDsaParameters& parameters) {
  absl::StatusOr<MlDsaInstanceEnumTP> ml_dsa_instance =
      ToProtoMlDsaInstance(parameters.GetMlDsaInstance());
  if (!ml_dsa_instance.ok()) {
    return ml_dsa_instance.status();
  }
  absl::StatusOr<CompositeMlDsaClassicalAlgorithmEnumTP> classical_algorithm =
      ToProtoClassicalAlgorithm(parameters.GetClassicalAlgorithm());
  if (!classical_algorithm.ok()) {
    return classical_algorithm.status();
  }
  CompositeMlDsaParamsTP params;
  params.set_ml_dsa_instance(*ml_dsa_instance);
  params.set_classical_algorithm(*classical_algorithm);
  return params;
}

absl::StatusOr<CompositeMlDsaParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing CompositeMlDsaParameters.");
  }
  CompositeMlDsaFormatTP proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError(
        "Failed to parse CompositeMlDsaKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }
  return ToParameters(key_template.output_prefix_type(),
                      proto_key_format.params().ml_dsa_instance(),
                      proto_key_format.params().classical_algorithm());
}

absl::StatusOr<CompositeMlDsaPublicKey> ParsePublicKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing CompositeMlDsaPublicKey.");
  }
  if (serialization.GetKeyMaterialTypeEnum() !=
      KeyMaterialTypeEnum::kAsymmetricPublic) {
    return absl::InvalidArgumentError(
        "Wrong key material type when parsing CompositeMlDsaPublicKey.");
  }

  CompositeMlDsaPublicKeyTP proto_key;
  if (!proto_key.ParseFromString(serialization.SerializedKeyProto().GetSecret(
          InsecureSecretKeyAccess::Get()))) {
    return absl::InvalidArgumentError(
        "Failed to parse CompositeMlDsaPublicKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      ToParameters(serialization.GetOutputPrefixTypeEnum(),
                   proto_key.params().ml_dsa_instance(),
                   proto_key.params().classical_algorithm());
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<SerializationRegistry*> serialization_registry =
      GetSerializationRegistry();
  if (!serialization_registry.ok()) {
    return serialization_registry.status();
  }

  // Parse ML-DSA Public Key
  RestrictedData ml_dsa_serialized_key(proto_key.ml_dsa_public_key().value(),
                                       InsecureSecretKeyAccess::Get());
  // Subkeys are always in raw format and have no id requirement.
  absl::StatusOr<ProtoKeySerialization> ml_dsa_serialization =
      ProtoKeySerialization::Create(
          proto_key.ml_dsa_public_key().type_url(),
          std::move(ml_dsa_serialized_key),
          proto_key.ml_dsa_public_key().key_material_type(),
          OutputPrefixTypeEnum::kRaw, /*id_requirement=*/absl::nullopt);
  if (!ml_dsa_serialization.ok()) {
    return ml_dsa_serialization.status();
  }
  absl::StatusOr<std::unique_ptr<Key>> parsed_ml_dsa_key =
      (*serialization_registry)->ParseKey(*ml_dsa_serialization, token);
  if (!parsed_ml_dsa_key.ok()) {
    return parsed_ml_dsa_key.status();
  }
  absl::StatusOr<std::unique_ptr<MlDsaPublicKey>> ml_dsa_public_key =
      DynamicCast<MlDsaPublicKey>(std::move(*parsed_ml_dsa_key));
  if (!ml_dsa_public_key.ok()) {
    return absl::InvalidArgumentError(
        "Parsed ML-DSA key is not an MlDsaPublicKey");
  }

  // Parse Classical Public Key
  RestrictedData classical_serialized_key(
      proto_key.classical_public_key().value(), InsecureSecretKeyAccess::Get());
  // Subkeys are always in raw format and have no id requirement.
  absl::StatusOr<ProtoKeySerialization> classical_serialization =
      ProtoKeySerialization::Create(
          proto_key.classical_public_key().type_url(),
          std::move(classical_serialized_key),
          proto_key.classical_public_key().key_material_type(),
          OutputPrefixTypeEnum::kRaw, /*id_requirement=*/absl::nullopt);
  if (!classical_serialization.ok()) {
    return classical_serialization.status();
  }
  absl::StatusOr<std::unique_ptr<Key>> parsed_classical_key =
      (*serialization_registry)->ParseKey(*classical_serialization, token);
  if (!parsed_classical_key.ok()) {
    return parsed_classical_key.status();
  }
  absl::StatusOr<std::unique_ptr<SignaturePublicKey>> classical_public_key =
      DynamicCast<SignaturePublicKey>(std::move(*parsed_classical_key));
  if (!classical_public_key.ok()) {
    return absl::InvalidArgumentError(
        "Parsed classical key is not a SignaturePublicKey");
  }

  return CompositeMlDsaPublicKey::Create(
      *parameters, **ml_dsa_public_key, std::move(*classical_public_key),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const CompositeMlDsaParameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  absl::StatusOr<CompositeMlDsaParamsTP> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }
  CompositeMlDsaFormatTP proto_key_format;
  *proto_key_format.mutable_params() = *params;
  proto_key_format.set_version(0);
  std::string serialized_proto = proto_key_format.SerializeAsString();
  return ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, serialized_proto);
}

absl::StatusOr<ProtoKeySerialization> SerializePublicKey(
    const CompositeMlDsaPublicKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<CompositeMlDsaParamsTP> params =
      FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  absl::StatusOr<SerializationRegistry*> serialization_registry =
      GetSerializationRegistry();
  if (!serialization_registry.ok()) {
    return serialization_registry.status();
  }

  // Serialize ML-DSA Public Key
  absl::StatusOr<std::unique_ptr<Serialization>> ml_dsa_serialization =
      (*serialization_registry)
          ->SerializeKey<ProtoKeySerialization>(key.GetMlDsaPublicKey(), token);
  if (!ml_dsa_serialization.ok()) {
    return ml_dsa_serialization.status();
  }
  absl::StatusOr<std::unique_ptr<ProtoKeySerialization>>
      ml_dsa_proto_key_serialization =
          DynamicCast<ProtoKeySerialization>(std::move(*ml_dsa_serialization));
  if (!ml_dsa_proto_key_serialization.ok()) {
    return ml_dsa_proto_key_serialization.status();
  }
  if ((*ml_dsa_proto_key_serialization)->GetOutputPrefixTypeEnum() !=
      OutputPrefixTypeEnum::kRaw) {
    return absl::InvalidArgumentError(
        "Require raw output prefix for ML-DSA public key.");
  }
  if ((*ml_dsa_proto_key_serialization)->IdRequirement().has_value()) {
    return absl::InvalidArgumentError(
        "ML-DSA public key cannot have ID requirement.");
  }
  KeyDataTP ml_dsa_key_data;
  ml_dsa_key_data.set_type_url((*ml_dsa_proto_key_serialization)->TypeUrl());
  ml_dsa_key_data.set_key_material_type(
      (*ml_dsa_proto_key_serialization)->GetKeyMaterialTypeEnum());
  ml_dsa_key_data.set_value((*ml_dsa_proto_key_serialization)
                                ->SerializedKeyProto()
                                .GetSecret(InsecureSecretKeyAccess::Get()));

  // Serialize Classical Public Key
  absl::StatusOr<std::unique_ptr<Serialization>> classical_serialization =
      (*serialization_registry)
          ->SerializeKey<ProtoKeySerialization>(key.GetClassicalPublicKey(),
                                                token);
  if (!classical_serialization.ok()) {
    return classical_serialization.status();
  }
  absl::StatusOr<std::unique_ptr<ProtoKeySerialization>>
      classical_proto_key_serialization = DynamicCast<ProtoKeySerialization>(
          std::move(*classical_serialization));
  if (!classical_proto_key_serialization.ok()) {
    return classical_proto_key_serialization.status();
  }
  if ((*classical_proto_key_serialization)->GetOutputPrefixTypeEnum() !=
      OutputPrefixTypeEnum::kRaw) {
    return absl::InvalidArgumentError(
        "Require raw output prefix for classical public key.");
  }
  if ((*classical_proto_key_serialization)->IdRequirement().has_value()) {
    return absl::InvalidArgumentError(
        "Classical public key cannot have ID requirement.");
  }
  KeyDataTP classical_key_data;
  classical_key_data.set_type_url(
      (*classical_proto_key_serialization)->TypeUrl());
  classical_key_data.set_key_material_type(
      (*classical_proto_key_serialization)->GetKeyMaterialTypeEnum());
  classical_key_data.set_value((*classical_proto_key_serialization)
                                   ->SerializedKeyProto()
                                   .GetSecret(InsecureSecretKeyAccess::Get()));

  CompositeMlDsaPublicKeyTP proto_key;
  proto_key.set_version(0);
  *proto_key.mutable_params() = *params;
  *proto_key.mutable_ml_dsa_public_key() = ml_dsa_key_data;
  *proto_key.mutable_classical_public_key() = classical_key_data;

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

CompositeMlDsaProtoParametersParserImpl& CompositeMlDsaProtoParametersParser() {
  static auto parser = new CompositeMlDsaProtoParametersParserImpl(
      kPrivateTypeUrl, ParseParameters);
  return *parser;
}

CompositeMlDsaProtoParametersSerializerImpl&
CompositeMlDsaProtoParametersSerializer() {
  static auto serializer = new CompositeMlDsaProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return *serializer;
}

CompositeMlDsaPublicKeyParserImpl& CompositeMlDsaPublicKeyParser() {
  static auto* parser =
      new CompositeMlDsaPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return *parser;
}

CompositeMlDsaPublicKeySerializerImpl& CompositeMlDsaPublicKeySerializer() {
  static auto* serializer =
      new CompositeMlDsaPublicKeySerializerImpl(SerializePublicKey);
  return *serializer;
}

}  // namespace

absl::Status RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  if (absl::Status status = registry.RegisterParametersParser(
          &CompositeMlDsaProtoParametersParser());
      !status.ok()) {
    return status;
  }
  if (absl::Status status = registry.RegisterParametersSerializer(
          &CompositeMlDsaProtoParametersSerializer());
      !status.ok()) {
    return status;
  }
  if (absl::Status status =
          registry.RegisterKeyParser(&CompositeMlDsaPublicKeyParser());
      !status.ok()) {
    return status;
  }
  return registry.RegisterKeySerializer(&CompositeMlDsaPublicKeySerializer());
}

absl::Status RegisterCompositeMlDsaProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  if (absl::Status status = builder.RegisterParametersParser(
          &CompositeMlDsaProtoParametersParser());
      !status.ok()) {
    return status;
  }
  if (absl::Status status = builder.RegisterParametersSerializer(
          &CompositeMlDsaProtoParametersSerializer());
      !status.ok()) {
    return status;
  }
  if (absl::Status status =
          builder.RegisterKeyParser(&CompositeMlDsaPublicKeyParser());
      !status.ok()) {
    return status;
  }
  return builder.RegisterKeySerializer(&CompositeMlDsaPublicKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
