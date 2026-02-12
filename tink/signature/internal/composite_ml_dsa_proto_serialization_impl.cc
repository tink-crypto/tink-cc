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
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/proto_parser_enum_field.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/signature/composite_ml_dsa_parameters.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::EnumField;
using ::crypto::tink::internal::proto_parsing::Field;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageField;
using ::crypto::tink::internal::proto_parsing::Uint32Field;

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

using CompositeMlDsaProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization,
                         CompositeMlDsaParameters>;
using CompositeMlDsaProtoParametersSerializerImpl =
    ParametersSerializerImpl<CompositeMlDsaParameters,
                             ProtoParametersSerialization>;

constexpr absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.CompositeMlDsaPrivateKey";

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

}  // namespace

absl::Status RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  if (absl::Status status = registry.RegisterParametersParser(
          &CompositeMlDsaProtoParametersParser());
      !status.ok()) {
    return status;
  }
  return registry.RegisterParametersSerializer(
      &CompositeMlDsaProtoParametersSerializer());
}

absl::Status RegisterCompositeMlDsaProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  if (absl::Status status = builder.RegisterParametersParser(
          &CompositeMlDsaProtoParametersParser());
      !status.ok()) {
    return status;
  }
  return builder.RegisterParametersSerializer(
      &CompositeMlDsaProtoParametersSerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
