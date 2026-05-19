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
#include "tink/jwt/jwt_ml_dsa_parameters.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::EnumField;
using ::crypto::tink::internal::proto_parsing::Field;
using ::crypto::tink::internal::proto_parsing::Message;
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

using JwtMlDsaProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, JwtMlDsaParameters>;
using JwtMlDsaProtoParametersSerializerImpl =
    ParametersSerializerImpl<JwtMlDsaParameters, ProtoParametersSerialization>;

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
    OutputPrefixTypeTP output_prefix_type,
    JwtMlDsaAlgorithmTP proto_algorithm, bool has_custom_kid) {
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

}  // namespace

absl::Status RegisterJwtMlDsaProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  if (absl::Status status =
          registry.RegisterParametersParser(&JwtMlDsaProtoParametersParser());
      !status.ok()) {
    return status;
  }

  return registry.RegisterParametersSerializer(
      &JwtMlDsaProtoParametersSerializer());
}

absl::Status RegisterJwtMlDsaProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  if (absl::Status status =
          builder.RegisterParametersParser(&JwtMlDsaProtoParametersParser());
      !status.ok()) {
    return status;
  }

  return builder.RegisterParametersSerializer(
      &JwtMlDsaProtoParametersSerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
