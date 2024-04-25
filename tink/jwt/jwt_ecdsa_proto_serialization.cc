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

#include "tink/jwt/jwt_ecdsa_proto_serialization.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::JwtEcdsaKeyFormat;
using ::google::crypto::tink::OutputPrefixType;

using JwtEcdsaProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   JwtEcdsaParameters>;
using JwtEcdsaProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<JwtEcdsaParameters,
                                       internal::ProtoParametersSerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey";

util::StatusOr<JwtEcdsaParameters::KidStrategy> ToKidStrategy(
    OutputPrefixType output_prefix_type, bool has_custom_kid) {
  switch (output_prefix_type) {
    case OutputPrefixType::RAW:
      if (has_custom_kid) {
        return JwtEcdsaParameters::KidStrategy::kCustom;
      }
      return JwtEcdsaParameters::KidStrategy::kIgnored;
    case OutputPrefixType::TINK:
      return JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid OutputPrefixType for JwtEcdsaKeyFormat.");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    JwtEcdsaParameters::KidStrategy kid_strategy) {
  switch (kid_strategy) {
    case JwtEcdsaParameters::KidStrategy::kCustom:
      return OutputPrefixType::RAW;
    case JwtEcdsaParameters::KidStrategy::kIgnored:
      return OutputPrefixType::RAW;
    case JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId:
      return OutputPrefixType::TINK;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine JwtEcdsaParameters::KidStrategy.");
  }
}

util::StatusOr<JwtEcdsaParameters::Algorithm> FromProtoAlgorithm(
    JwtEcdsaAlgorithm algorithm) {
  switch (algorithm) {
    case JwtEcdsaAlgorithm::ES256:
      return JwtEcdsaParameters::Algorithm::kEs256;
    case JwtEcdsaAlgorithm::ES384:
      return JwtEcdsaParameters::Algorithm::kEs384;
    case JwtEcdsaAlgorithm::ES512:
      return JwtEcdsaParameters::Algorithm::kEs512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine JwtEcdsaAlgorithm.");
  }
}

util::StatusOr<JwtEcdsaAlgorithm> ToProtoAlgorithm(
    JwtEcdsaParameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtEcdsaParameters::Algorithm::kEs256:
      return JwtEcdsaAlgorithm::ES256;
    case JwtEcdsaParameters::Algorithm::kEs384:
      return JwtEcdsaAlgorithm::ES384;
    case JwtEcdsaParameters::Algorithm::kEs512:
      return JwtEcdsaAlgorithm::ES512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine JwtEcdsaParameters::Algorithm");
  }
}

util::StatusOr<JwtEcdsaParameters> ToParameters(
    OutputPrefixType output_prefix_type, JwtEcdsaAlgorithm proto_algorithm,
    bool has_custom_kid) {
  util::StatusOr<JwtEcdsaParameters::KidStrategy> kid_strategy =
      ToKidStrategy(output_prefix_type, has_custom_kid);
  if (!kid_strategy.ok()) {
    return kid_strategy.status();
  }
  util::StatusOr<JwtEcdsaParameters::Algorithm> algorithm =
      FromProtoAlgorithm(proto_algorithm);
  if (!algorithm.ok()) {
    return algorithm.status();
  }
  return JwtEcdsaParameters::Create(*kid_strategy, *algorithm);
}

util::StatusOr<JwtEcdsaParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing JwtEcdsaParameters.");
  }
  JwtEcdsaKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse JwtEcdsaKeyFormat proto.");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing JwtEcdsaParameters failed: only version 0 is accepted.");
  }

  return ToParameters(serialization.GetKeyTemplate().output_prefix_type(),
                      proto_key_format.algorithm(), /*has_custom_kid=*/false);
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const JwtEcdsaParameters& parameters) {
  if (parameters.GetKidStrategy() == JwtEcdsaParameters::KidStrategy::kCustom) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Unable to serialize JwtEcdsaParameters::KidStrategy::kCustom.");
  }
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  util::StatusOr<JwtEcdsaAlgorithm> proto_algorithm =
      ToProtoAlgorithm(parameters.GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  JwtEcdsaKeyFormat format;
  format.set_version(0);
  format.set_algorithm(*proto_algorithm);

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, format.SerializeAsString());
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

}  // namespace

util::Status RegisterJwtEcdsaProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(&JwtEcdsaProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterParametersSerializer(&JwtEcdsaProtoParametersSerializer());
}

}  // namespace tink
}  // namespace crypto
