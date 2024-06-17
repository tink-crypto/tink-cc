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

#include "tink/jwt/jwt_rsa_ssa_pss_proto_serialization.h"

#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pss_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/jwt_rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::JwtRsaSsaPssAlgorithm;
using ::google::crypto::tink::JwtRsaSsaPssKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;

using JwtRsaSsaPssProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   JwtRsaSsaPssParameters>;
using JwtRsaSsaPssProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<JwtRsaSsaPssParameters,
                                       internal::ProtoParametersSerialization>;
using JwtRsaSsaPssProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            JwtRsaSsaPssPublicKey>;
using JwtRsaSsaPssProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<JwtRsaSsaPssPublicKey,
                                internal::ProtoKeySerialization>;
using JwtRsaSsaPssProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            JwtRsaSsaPssPrivateKey>;
using JwtRsaSsaPssProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<JwtRsaSsaPssPrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey";

util::StatusOr<JwtRsaSsaPssParameters::KidStrategy> ToKidStrategy(
    OutputPrefixType output_prefix_type, bool has_custom_kid) {
  switch (output_prefix_type) {
    case OutputPrefixType::RAW:
      if (has_custom_kid) {
        return JwtRsaSsaPssParameters::KidStrategy::kCustom;
      }
      return JwtRsaSsaPssParameters::KidStrategy::kIgnored;
    case OutputPrefixType::TINK:
      return JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Invalid OutputPrefixType for JwtRsaSsaPssKeyFormat.");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    JwtRsaSsaPssParameters::KidStrategy kid_strategy) {
  switch (kid_strategy) {
    case JwtRsaSsaPssParameters::KidStrategy::kCustom:
    case JwtRsaSsaPssParameters::KidStrategy::kIgnored:
      return OutputPrefixType::RAW;
    case JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId:
      return OutputPrefixType::TINK;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine JwtRsaSsaPssParameters::KidStrategy.");
  }
}

util::StatusOr<JwtRsaSsaPssParameters::Algorithm> FromProtoAlgorithm(
    JwtRsaSsaPssAlgorithm algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPssAlgorithm::PS256:
      return JwtRsaSsaPssParameters::Algorithm::kPs256;
    case JwtRsaSsaPssAlgorithm::PS384:
      return JwtRsaSsaPssParameters::Algorithm::kPs384;
    case JwtRsaSsaPssAlgorithm::PS512:
      return JwtRsaSsaPssParameters::Algorithm::kPs512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine JwtRsaSsaPssAlgorithm.");
  }
}

util::StatusOr<JwtRsaSsaPssAlgorithm> ToProtoAlgorithm(
    JwtRsaSsaPssParameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPssParameters::Algorithm::kPs256:
      return JwtRsaSsaPssAlgorithm::PS256;
    case JwtRsaSsaPssParameters::Algorithm::kPs384:
      return JwtRsaSsaPssAlgorithm::PS384;
    case JwtRsaSsaPssParameters::Algorithm::kPs512:
      return JwtRsaSsaPssAlgorithm::PS512;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine JwtRsaSsaPssParameters::Algorithm");
  }
}

util::StatusOr<JwtRsaSsaPssParameters> ToParameters(
    OutputPrefixType output_prefix_type,
    JwtRsaSsaPssAlgorithm proto_algorithm, int modulus_size_in_bits,
    const BigInteger& public_exponent, bool has_custom_kid) {
  util::StatusOr<JwtRsaSsaPssParameters::KidStrategy> kid_strategy =
      ToKidStrategy(output_prefix_type, has_custom_kid);
  if (!kid_strategy.ok()) {
    return kid_strategy.status();
  }

  util::StatusOr<JwtRsaSsaPssParameters::Algorithm> algorithm =
      FromProtoAlgorithm(proto_algorithm);
  if (!algorithm.ok()) {
    return algorithm.status();
  }

  return JwtRsaSsaPssParameters::Builder()
      .SetKidStrategy(*kid_strategy)
      .SetAlgorithm(*algorithm)
      .SetModulusSizeInBits(modulus_size_in_bits)
      .SetPublicExponent(public_exponent)
      .Build();
}

util::StatusOr<JwtRsaSsaPssPublicKey> ToPublicKey(
    const google::crypto::tink::JwtRsaSsaPssPublicKey& proto_public_key,
    OutputPrefixType output_prefix_type, absl::optional<int> id_requirement) {
  BigInteger modulus(proto_public_key.n());
  int modulus_size_in_bits = modulus.SizeInBytes() * 8;

  util::StatusOr<JwtRsaSsaPssParameters> parameters = ToParameters(
      output_prefix_type, proto_public_key.algorithm(), modulus_size_in_bits,
      BigInteger(proto_public_key.e()), proto_public_key.has_custom_kid());
  if (!parameters.ok()) {
    return parameters.status();
  }

  JwtRsaSsaPssPublicKey::Builder builder = JwtRsaSsaPssPublicKey::Builder()
                                                 .SetParameters(*parameters)
                                                 .SetModulus(modulus);
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(*id_requirement);
  }
  if (proto_public_key.has_custom_kid()) {
    builder.SetCustomKid(proto_public_key.custom_kid().value());
  }
  return builder.Build(GetPartialKeyAccess());
}

util::StatusOr<JwtRsaSsaPssParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing JwtRsaSsaPssParameters.");
  }

  JwtRsaSsaPssKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse JwtRsaSsaPssKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing JwtRsaSsaPssParameters failed: only version 0 is accepted.");
  }

  return ToParameters(
      serialization.GetKeyTemplate().output_prefix_type(),
      proto_key_format.algorithm(), proto_key_format.modulus_size_in_bits(),
      BigInteger(proto_key_format.public_exponent()), /*has_custom_kid=*/false);
}

util::StatusOr<JwtRsaSsaPssPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing JwtRsaSsaPssPublicKey.");
  }

  google::crypto::tink::JwtRsaSsaPssPublicKey proto_public_key;
  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  if (!proto_public_key.ParseFromString(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse JwtRsaSsaPssPublicKey proto");
  }
  if (proto_public_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  return ToPublicKey(proto_public_key, serialization.GetOutputPrefixType(),
                     serialization.IdRequirement());
}

util::StatusOr<JwtRsaSsaPssPrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing JwtRsaSsaPssPrivateKey.");
  }

  absl::StatusOr<SecretProto<google::crypto::tink::JwtRsaSsaPssPrivateKey>>
      proto_key = SecretProto<google::crypto::tink::JwtRsaSsaPssPrivateKey>::
          ParseFromSecretData(serialization.SerializedKeyProto().Get(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse JwtRsaSsaPssPrivateKey proto");
  }
  if ((*proto_key)->version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }
  if (!(*proto_key)->has_public_key()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "JwtRsaSsaPssPrivateKey proto is missing public key.");
  }

  util::StatusOr<JwtRsaSsaPssPublicKey> public_key = ToPublicKey(
      (*proto_key)->public_key(), serialization.GetOutputPrefixType(),
      serialization.IdRequirement());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return JwtRsaSsaPssPrivateKey::Builder()
      .SetPublicKey(*public_key)
      .SetPrimeP(RestrictedBigInteger((*proto_key)->p(), *token))
      .SetPrimeQ(RestrictedBigInteger((*proto_key)->q(), *token))
      .SetPrimeExponentP(RestrictedBigInteger((*proto_key)->dp(), *token))
      .SetPrimeExponentQ(RestrictedBigInteger((*proto_key)->dq(), *token))
      .SetPrivateExponent(RestrictedBigInteger((*proto_key)->d(), *token))
      .SetCrtCoefficient(RestrictedBigInteger((*proto_key)->crt(), *token))
      .Build(GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const JwtRsaSsaPssParameters& parameters) {
  if (parameters.GetKidStrategy() ==
      JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Unable to serialize JwtRsaSsaPssParameters::KidStrategy::kCustom.");
  }
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  util::StatusOr<JwtRsaSsaPssAlgorithm> proto_algorithm =
      ToProtoAlgorithm(parameters.GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  JwtRsaSsaPssKeyFormat key_format;
  key_format.set_version(0);
  key_format.set_algorithm(*proto_algorithm);
  key_format.set_modulus_size_in_bits(parameters.GetModulusSizeInBits());
  key_format.set_public_exponent(parameters.GetPublicExponent().GetValue());

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, key_format.SerializeAsString());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const JwtRsaSsaPssPublicKey& public_key,
    absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<JwtRsaSsaPssAlgorithm> proto_algorithm =
      ToProtoAlgorithm(public_key.GetParameters().GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  google::crypto::tink::JwtRsaSsaPssPublicKey proto_public_key;
  proto_public_key.set_version(0);
  proto_public_key.set_algorithm(*proto_algorithm);
  proto_public_key.set_n(
      public_key.GetModulus(GetPartialKeyAccess()).GetValue());
  proto_public_key.set_e(
      public_key.GetParameters().GetPublicExponent().GetValue());
  if (public_key.GetParameters().GetKidStrategy() ==
      JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    proto_public_key.mutable_custom_kid()->set_value(*public_key.GetKid());
  }

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(public_key.GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output = RestrictedData(
      proto_public_key.SerializeAsString(), InsecureSecretKeyAccess::Get());
  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl, std::move(restricted_output), KeyData::ASYMMETRIC_PUBLIC,
      *output_prefix_type, public_key.GetIdRequirement());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePrivateKey(
    const JwtRsaSsaPssPrivateKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  util::StatusOr<JwtRsaSsaPssAlgorithm> proto_algorithm =
      ToProtoAlgorithm(key.GetPublicKey().GetParameters().GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }
  google::crypto::tink::JwtRsaSsaPssPublicKey proto_public_key;
  proto_public_key.set_version(0);
  proto_public_key.set_algorithm(*proto_algorithm);
  proto_public_key.set_n(
      key.GetPublicKey().GetModulus(GetPartialKeyAccess()).GetValue());
  proto_public_key.set_e(
      key.GetPublicKey().GetParameters().GetPublicExponent().GetValue());
  if (key.GetPublicKey().GetParameters().GetKidStrategy() ==
      JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    proto_public_key.mutable_custom_kid()->set_value(
        *key.GetPublicKey().GetKid());
  }

  SecretProto<google::crypto::tink::JwtRsaSsaPssPrivateKey> proto_private_key;
  proto_private_key->set_version(0);
  *proto_private_key->mutable_public_key() = proto_public_key;
  internal::CallWithCoreDumpProtection([&]() {
    proto_private_key->set_p(
        key.GetPrimeP(GetPartialKeyAccess()).GetSecret(*token));
    proto_private_key->set_q(
        key.GetPrimeQ(GetPartialKeyAccess()).GetSecret(*token));
    proto_private_key->set_dp(key.GetPrimeExponentP().GetSecret(*token));
    proto_private_key->set_dq(key.GetPrimeExponentQ().GetSecret(*token));
    proto_private_key->set_d(key.GetPrivateExponent().GetSecret(*token));
    proto_private_key->set_crt(key.GetCrtCoefficient().GetSecret(*token));
  });

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<SecretData> serialized_key =
      proto_private_key.SerializeAsSecretData();
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*std::move(serialized_key), *token);
  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl, std::move(restricted_output),
      KeyData::ASYMMETRIC_PRIVATE, *output_prefix_type, key.GetIdRequirement());
}

JwtRsaSsaPssProtoParametersParserImpl& JwtRsaSsaPssProtoParametersParser() {
  static auto* parser = new JwtRsaSsaPssProtoParametersParserImpl(
      kPrivateTypeUrl, ParseParameters);
  return *parser;
}

JwtRsaSsaPssProtoParametersSerializerImpl&
JwtRsaSsaPssProtoParametersSerializer() {
  static auto* serializer = new JwtRsaSsaPssProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return *serializer;
}

JwtRsaSsaPssProtoPublicKeyParserImpl& JwtRsaSsaPssProtoPublicKeyParser() {
  static auto* parser = new JwtRsaSsaPssProtoPublicKeyParserImpl(
      kPublicTypeUrl, ParsePublicKey);
  return *parser;
}

JwtRsaSsaPssProtoPublicKeySerializerImpl&
JwtRsaSsaPssProtoPublicKeySerializer() {
  static auto* serializer =
      new JwtRsaSsaPssProtoPublicKeySerializerImpl(SerializePublicKey);
  return *serializer;
}

JwtRsaSsaPssProtoPrivateKeyParserImpl& JwtRsaSsaPssProtoPrivateKeyParser() {
  static auto* parser = new JwtRsaSsaPssProtoPrivateKeyParserImpl(
      kPrivateTypeUrl, ParsePrivateKey);
  return *parser;
}

JwtRsaSsaPssProtoPrivateKeySerializerImpl&
JwtRsaSsaPssProtoPrivateKeySerializer() {
  static auto* serializer =
      new JwtRsaSsaPssProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return *serializer;
}

}  // namespace

util::Status RegisterJwtRsaSsaPssProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(&JwtRsaSsaPssProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(
                   &JwtRsaSsaPssProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&JwtRsaSsaPssProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterKeySerializer(&JwtRsaSsaPssProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&JwtRsaSsaPssProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(&JwtRsaSsaPssProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
