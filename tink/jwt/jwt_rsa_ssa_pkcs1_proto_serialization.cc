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

#include "tink/jwt/jwt_rsa_ssa_pkcs1_proto_serialization.h"

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
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/jwt_rsa_ssa_pkcs1.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::JwtRsaSsaPkcs1Algorithm;
using ::google::crypto::tink::JwtRsaSsaPkcs1KeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;

using JwtRsaSsaPkcs1ProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   JwtRsaSsaPkcs1Parameters>;
using JwtRsaSsaPkcs1ProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<JwtRsaSsaPkcs1Parameters,
                                       internal::ProtoParametersSerialization>;
using JwtRsaSsaPkcs1ProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            JwtRsaSsaPkcs1PublicKey>;
using JwtRsaSsaPkcs1ProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<JwtRsaSsaPkcs1PublicKey,
                                internal::ProtoKeySerialization>;
using JwtRsaSsaPkcs1ProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            JwtRsaSsaPkcs1PrivateKey>;
using JwtRsaSsaPkcs1ProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<JwtRsaSsaPkcs1PrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey";

util::StatusOr<JwtRsaSsaPkcs1Parameters::KidStrategy> ToKidStrategy(
    OutputPrefixType output_prefix_type, bool has_custom_kid) {
  switch (output_prefix_type) {
    case OutputPrefixType::RAW:
      if (has_custom_kid) {
        return JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom;
      }
      return JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored;
    case OutputPrefixType::TINK:
      return JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Invalid OutputPrefixType for JwtRsaSsaPkcs1KeyFormat.");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    JwtRsaSsaPkcs1Parameters::KidStrategy kid_strategy) {
  switch (kid_strategy) {
    case JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom:
    case JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored:
      return OutputPrefixType::RAW;
    case JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId:
      return OutputPrefixType::TINK;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine JwtRsaSsaPkcs1Parameters::KidStrategy.");
  }
}

util::StatusOr<JwtRsaSsaPkcs1Parameters::Algorithm> FromProtoAlgorithm(
    JwtRsaSsaPkcs1Algorithm algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPkcs1Algorithm::RS256:
      return JwtRsaSsaPkcs1Parameters::Algorithm::kRs256;
    case JwtRsaSsaPkcs1Algorithm::RS384:
      return JwtRsaSsaPkcs1Parameters::Algorithm::kRs384;
    case JwtRsaSsaPkcs1Algorithm::RS512:
      return JwtRsaSsaPkcs1Parameters::Algorithm::kRs512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine JwtRsaSsaPkcs1Algorithm.");
  }
}

util::StatusOr<JwtRsaSsaPkcs1Algorithm> ToProtoAlgorithm(
    JwtRsaSsaPkcs1Parameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPkcs1Parameters::Algorithm::kRs256:
      return JwtRsaSsaPkcs1Algorithm::RS256;
    case JwtRsaSsaPkcs1Parameters::Algorithm::kRs384:
      return JwtRsaSsaPkcs1Algorithm::RS384;
    case JwtRsaSsaPkcs1Parameters::Algorithm::kRs512:
      return JwtRsaSsaPkcs1Algorithm::RS512;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine JwtRsaSsaPkcs1Parameters::Algorithm");
  }
}

util::StatusOr<JwtRsaSsaPkcs1Parameters> ToParameters(
    OutputPrefixType output_prefix_type,
    JwtRsaSsaPkcs1Algorithm proto_algorithm, int modulus_size_in_bits,
    const BigInteger& public_exponent, bool has_custom_kid) {
  util::StatusOr<JwtRsaSsaPkcs1Parameters::KidStrategy> kid_strategy =
      ToKidStrategy(output_prefix_type, has_custom_kid);
  if (!kid_strategy.ok()) {
    return kid_strategy.status();
  }

  util::StatusOr<JwtRsaSsaPkcs1Parameters::Algorithm> algorithm =
      FromProtoAlgorithm(proto_algorithm);
  if (!algorithm.ok()) {
    return algorithm.status();
  }

  return JwtRsaSsaPkcs1Parameters::Builder()
      .SetKidStrategy(*kid_strategy)
      .SetAlgorithm(*algorithm)
      .SetModulusSizeInBits(modulus_size_in_bits)
      .SetPublicExponent(public_exponent)
      .Build();
}

util::StatusOr<JwtRsaSsaPkcs1PublicKey> ToPublicKey(
    const google::crypto::tink::JwtRsaSsaPkcs1PublicKey& proto_public_key,
    OutputPrefixType output_prefix_type, absl::optional<int> id_requirement) {
  BigInteger modulus(proto_public_key.n());
  int modulus_size_in_bits = modulus.SizeInBytes() * 8;

  util::StatusOr<JwtRsaSsaPkcs1Parameters> parameters = ToParameters(
      output_prefix_type, proto_public_key.algorithm(), modulus_size_in_bits,
      BigInteger(proto_public_key.e()), proto_public_key.has_custom_kid());
  if (!parameters.ok()) {
    return parameters.status();
  }

  JwtRsaSsaPkcs1PublicKey::Builder builder = JwtRsaSsaPkcs1PublicKey::Builder()
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

util::StatusOr<JwtRsaSsaPkcs1Parameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing JwtRsaSsaPkcs1Parameters.");
  }

  JwtRsaSsaPkcs1KeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse JwtRsaSsaPkcs1KeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing JwtRsaSsaPkcs1Parameters failed: only version 0 is accepted.");
  }

  return ToParameters(
      serialization.GetKeyTemplate().output_prefix_type(),
      proto_key_format.algorithm(), proto_key_format.modulus_size_in_bits(),
      BigInteger(proto_key_format.public_exponent()), /*has_custom_kid=*/false);
}

util::StatusOr<JwtRsaSsaPkcs1PublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing JwtRsaSsaPkcs1PublicKey.");
  }

  google::crypto::tink::JwtRsaSsaPkcs1PublicKey proto_public_key;
  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  if (!proto_public_key.ParseFromString(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse JwtRsaSsaPkcs1PublicKey proto");
  }
  if (proto_public_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  return ToPublicKey(proto_public_key, serialization.GetOutputPrefixType(),
                     serialization.IdRequirement());
}

util::StatusOr<JwtRsaSsaPkcs1PrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing JwtRsaSsaPkcs1PrivateKey.");
  }

  absl::StatusOr<SecretProto<google::crypto::tink::JwtRsaSsaPkcs1PrivateKey>>
      proto_key = SecretProto<google::crypto::tink::JwtRsaSsaPkcs1PrivateKey>::
          ParseFromSecretData(serialization.SerializedKeyProto().Get(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse JwtRsaSsaPkcs1PrivateKey proto");
  }
  if ((*proto_key)->version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }
  if (!(*proto_key)->has_public_key()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "JwtRsaSsaPkcs1PrivateKey proto is missing public key.");
  }

  if ((*proto_key)->public_key().version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 public keys are accepted.");
  }

  util::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key = ToPublicKey(
      (*proto_key)->public_key(), serialization.GetOutputPrefixType(),
      serialization.IdRequirement());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return JwtRsaSsaPkcs1PrivateKey::Builder()
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
    const JwtRsaSsaPkcs1Parameters& parameters) {
  if (parameters.GetKidStrategy() ==
      JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Unable to serialize JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom.");
  }
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  util::StatusOr<JwtRsaSsaPkcs1Algorithm> proto_algorithm =
      ToProtoAlgorithm(parameters.GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  JwtRsaSsaPkcs1KeyFormat key_format;
  key_format.set_version(0);
  key_format.set_algorithm(*proto_algorithm);
  key_format.set_modulus_size_in_bits(parameters.GetModulusSizeInBits());
  key_format.set_public_exponent(parameters.GetPublicExponent().GetValue());

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, key_format.SerializeAsString());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const JwtRsaSsaPkcs1PublicKey& public_key,
    absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<JwtRsaSsaPkcs1Algorithm> proto_algorithm =
      ToProtoAlgorithm(public_key.GetParameters().GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  google::crypto::tink::JwtRsaSsaPkcs1PublicKey proto_public_key;
  proto_public_key.set_version(0);
  proto_public_key.set_algorithm(*proto_algorithm);
  proto_public_key.set_n(
      public_key.GetModulus(GetPartialKeyAccess()).GetValue());
  proto_public_key.set_e(
      public_key.GetParameters().GetPublicExponent().GetValue());
  if (public_key.GetParameters().GetKidStrategy() ==
      JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
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
    const JwtRsaSsaPkcs1PrivateKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  util::StatusOr<JwtRsaSsaPkcs1Algorithm> proto_algorithm =
      ToProtoAlgorithm(key.GetPublicKey().GetParameters().GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }
  google::crypto::tink::JwtRsaSsaPkcs1PublicKey proto_public_key;
  proto_public_key.set_version(0);
  proto_public_key.set_algorithm(*proto_algorithm);
  proto_public_key.set_n(
      key.GetPublicKey().GetModulus(GetPartialKeyAccess()).GetValue());
  proto_public_key.set_e(
      key.GetPublicKey().GetParameters().GetPublicExponent().GetValue());
  if (key.GetPublicKey().GetParameters().GetKidStrategy() ==
      JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    proto_public_key.mutable_custom_kid()->set_value(
        *key.GetPublicKey().GetKid());
  }

  SecretProto<google::crypto::tink::JwtRsaSsaPkcs1PrivateKey> proto_private_key;
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

JwtRsaSsaPkcs1ProtoParametersParserImpl& JwtRsaSsaPkcs1ProtoParametersParser() {
  static auto* parser = new JwtRsaSsaPkcs1ProtoParametersParserImpl(
      kPrivateTypeUrl, ParseParameters);
  return *parser;
}

JwtRsaSsaPkcs1ProtoParametersSerializerImpl&
JwtRsaSsaPkcs1ProtoParametersSerializer() {
  static auto* serializer = new JwtRsaSsaPkcs1ProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return *serializer;
}

JwtRsaSsaPkcs1ProtoPublicKeyParserImpl& JwtRsaSsaPkcs1ProtoPublicKeyParser() {
  static auto* parser = new JwtRsaSsaPkcs1ProtoPublicKeyParserImpl(
      kPublicTypeUrl, ParsePublicKey);
  return *parser;
}

JwtRsaSsaPkcs1ProtoPublicKeySerializerImpl&
JwtRsaSsaPkcs1ProtoPublicKeySerializer() {
  static auto* serializer =
      new JwtRsaSsaPkcs1ProtoPublicKeySerializerImpl(SerializePublicKey);
  return *serializer;
}

JwtRsaSsaPkcs1ProtoPrivateKeyParserImpl& JwtRsaSsaPkcs1ProtoPrivateKeyParser() {
  static auto* parser = new JwtRsaSsaPkcs1ProtoPrivateKeyParserImpl(
      kPrivateTypeUrl, ParsePrivateKey);
  return *parser;
}

JwtRsaSsaPkcs1ProtoPrivateKeySerializerImpl&
JwtRsaSsaPkcs1ProtoPrivateKeySerializer() {
  static auto* serializer =
      new JwtRsaSsaPkcs1ProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return *serializer;
}

}  // namespace

util::Status RegisterJwtRsaSsaPkcs1ProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(&JwtRsaSsaPkcs1ProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(
                   &JwtRsaSsaPkcs1ProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&JwtRsaSsaPkcs1ProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterKeySerializer(&JwtRsaSsaPkcs1ProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&JwtRsaSsaPkcs1ProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(&JwtRsaSsaPkcs1ProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
