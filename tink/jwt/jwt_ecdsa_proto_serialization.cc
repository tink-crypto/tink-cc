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

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_encoding_util.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_private_key.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
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
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;

using JwtEcdsaProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   JwtEcdsaParameters>;
using JwtEcdsaProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<JwtEcdsaParameters,
                                       internal::ProtoParametersSerialization>;
using JwtEcdsaProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, JwtEcdsaPublicKey>;
using JwtEcdsaProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<JwtEcdsaPublicKey,
                                internal::ProtoKeySerialization>;
using JwtEcdsaProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            JwtEcdsaPrivateKey>;
using JwtEcdsaProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<JwtEcdsaPrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey";
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

util::StatusOr<int> GetEncodingLength(JwtEcdsaParameters::Algorithm algorithm) {
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
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Unable to determine JwtEcdsaParameters::Algorithm.");
  }
}

util::StatusOr<JwtEcdsaPublicKey> ToPublicKey(
    const JwtEcdsaParameters& parameters,
    const google::crypto::tink::JwtEcdsaPublicKey& proto_public_key,
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

util::StatusOr<google::crypto::tink::JwtEcdsaPublicKey> ToProtoPublicKey(
    const JwtEcdsaPublicKey& public_key) {
  util::StatusOr<JwtEcdsaAlgorithm> proto_algorithm =
      ToProtoAlgorithm(public_key.GetParameters().GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  util::StatusOr<int> enc_length =
      GetEncodingLength(public_key.GetParameters().GetAlgorithm());
  if (!enc_length.ok()) {
    return enc_length.status();
  }

  util::StatusOr<std::string> x = internal::GetValueOfFixedLength(
      public_key.GetPublicPoint(GetPartialKeyAccess()).GetX().GetValue(),
      *enc_length);
  if (!x.ok()) {
    return x.status();
  }

  util::StatusOr<std::string> y = internal::GetValueOfFixedLength(
      public_key.GetPublicPoint(GetPartialKeyAccess()).GetY().GetValue(),
      *enc_length);
  if (!y.ok()) {
    return y.status();
  }

  google::crypto::tink::JwtEcdsaPublicKey proto_public_key;
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

util::StatusOr<JwtEcdsaPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing JwtEcdsaPublicKey.");
  }

  google::crypto::tink::JwtEcdsaPublicKey proto_key;
  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  if (!proto_key.ParseFromString(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse JwtEcdsaPublicKey proto.");
  }
  if (proto_key.version() != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing JwtEcdsaPublicKey failed: only version 0 is accepted.");
  }

  util::StatusOr<JwtEcdsaParameters> parameters =
      ToParameters(serialization.GetOutputPrefixType(), proto_key.algorithm(),
                   proto_key.has_custom_kid());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return ToPublicKey(*parameters, proto_key, serialization.IdRequirement());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const JwtEcdsaPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<google::crypto::tink::JwtEcdsaPublicKey> proto_public_key =
      ToProtoPublicKey(key);
  if (!proto_public_key.ok()) {
    proto_public_key.status();
  }

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output = RestrictedData(
      proto_public_key->SerializeAsString(), InsecureSecretKeyAccess::Get());
  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl, std::move(restricted_output), KeyData::ASYMMETRIC_PUBLIC,
      *output_prefix_type, key.GetIdRequirement());
}

util::StatusOr<JwtEcdsaPrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing JwtEcdsaPrivateKey.");
  }

  util::SecretProto<google::crypto::tink::JwtEcdsaPrivateKey> proto_key;
  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  if (!internal::CallWithCoreDumpProtection([&]() {
        return proto_key->ParseFromString(restricted_data.GetSecret(*token));
      })) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse JwtEcdsaPrivateKey proto");
  }
  if (proto_key->version() != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing JwtEcdsaPrivateKey failed: only version 0 is accepted.");
  }
  if (!proto_key->has_public_key()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "JwtEcdsaPrivateKey proto is missing public key.");
  }

  util::StatusOr<JwtEcdsaParameters> parameters = ToParameters(
      serialization.GetOutputPrefixType(), proto_key->public_key().algorithm(),
      proto_key->public_key().has_custom_kid());
  if (!parameters.ok()) {
    return parameters.status();
  }

  util::StatusOr<JwtEcdsaPublicKey> public_key = ToPublicKey(
      *parameters, proto_key->public_key(), serialization.IdRequirement());
  if (!public_key.ok()) {
    return public_key.status();
  }

  RestrictedBigInteger private_key_value = internal::CallWithCoreDumpProtection(
      [&]() { return RestrictedBigInteger(proto_key->key_value(), *token); });
  return JwtEcdsaPrivateKey::Create(*public_key, private_key_value,
                                    GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePrivateKey(
    const JwtEcdsaPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  util::StatusOr<google::crypto::tink::JwtEcdsaPublicKey> proto_public_key =
      ToProtoPublicKey(key.GetPublicKey());
  if (!proto_public_key.ok()) {
    return proto_public_key.status();
  }

  util::StatusOr<RestrictedBigInteger> restricted_input =
      key.GetPrivateKeyValue(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  util::StatusOr<int> enc_length =
      GetEncodingLength(key.GetPublicKey().GetParameters().GetAlgorithm());
  if (!enc_length.ok()) {
    return enc_length.status();
  }

  util::SecretProto<google::crypto::tink::JwtEcdsaPrivateKey> proto_private_key;
  proto_private_key->set_version(0);
  *proto_private_key->mutable_public_key() = *std::move(proto_public_key);
  internal::CallWithCoreDumpProtection([&]() {
    proto_private_key->set_key_value(
        util::SecretDataAsStringView(*internal::GetSecretValueOfFixedLength(
            *restricted_input, *enc_length, *token)));
  });

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<util::SecretData> serialized_proto_private_key =
      proto_private_key.SerializeAsSecretData();
  if (!serialized_proto_private_key.ok()) {
    return serialized_proto_private_key.status();
  }
  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl,
      RestrictedData(*std::move(serialized_proto_private_key),
                     InsecureSecretKeyAccess::Get()),
      KeyData::ASYMMETRIC_PRIVATE, *output_prefix_type, key.GetIdRequirement());
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

util::Status RegisterJwtEcdsaProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(&JwtEcdsaProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersSerializer(&JwtEcdsaProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&JwtEcdsaProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeySerializer(&JwtEcdsaProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&JwtEcdsaProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(&JwtEcdsaProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
