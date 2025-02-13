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

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/proto_parser.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/jwt_rsa_ssa_pkcs1.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;
using ::crypto::tink::util::SecretData;
using ::google::crypto::tink::JwtRsaSsaPkcs1Algorithm;
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

bool JwtRsaSsaPkcs1AlgorithmValid(int value) {
  return google::crypto::tink::JwtRsaSsaPkcs1Algorithm_IsValid(value);
}

struct CustomKidStruct {
  std::string value;

  static ProtoParser<CustomKidStruct> CreateParser() {
    return ProtoParserBuilder<CustomKidStruct>()
        .AddBytesStringField(1, &CustomKidStruct::value)
        .BuildOrDie();
  }
};

struct JwtRsaSsaPkcs1PublicKeyStruct {
  uint32_t version;
  JwtRsaSsaPkcs1Algorithm algorithm;
  std::string n;
  std::string e;
  std::optional<CustomKidStruct> custom_kid;

  static ProtoParser<JwtRsaSsaPkcs1PublicKeyStruct> CreateParser() {
    return ProtoParserBuilder<JwtRsaSsaPkcs1PublicKeyStruct>()
        .AddUint32Field(1, &JwtRsaSsaPkcs1PublicKeyStruct::version)
        .AddEnumField(2, &JwtRsaSsaPkcs1PublicKeyStruct::algorithm,
                      &JwtRsaSsaPkcs1AlgorithmValid)
        .AddBytesStringField(3, &JwtRsaSsaPkcs1PublicKeyStruct::n)
        .AddBytesStringField(4, &JwtRsaSsaPkcs1PublicKeyStruct::e)
        .AddMessageFieldWithPresence(5,
                                     &JwtRsaSsaPkcs1PublicKeyStruct::custom_kid,
                                     CustomKidStruct::CreateParser())
        .BuildOrDie();
  }

  static const ProtoParser<JwtRsaSsaPkcs1PublicKeyStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<JwtRsaSsaPkcs1PublicKeyStruct>>
        parser{CreateParser()};
    return *parser;
  }
};

struct JwtRsaSsaPkcs1PrivateKeyStruct {
  uint32_t version;
  JwtRsaSsaPkcs1PublicKeyStruct public_key;
  SecretData d;
  SecretData p;
  SecretData q;
  SecretData dp;
  SecretData dq;
  SecretData crt;

  static const ProtoParser<JwtRsaSsaPkcs1PrivateKeyStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<JwtRsaSsaPkcs1PrivateKeyStruct>>
        parser{
            ProtoParserBuilder<JwtRsaSsaPkcs1PrivateKeyStruct>()
                .AddUint32Field(1, &JwtRsaSsaPkcs1PrivateKeyStruct::version)
                .AddMessageField(2, &JwtRsaSsaPkcs1PrivateKeyStruct::public_key,
                                 JwtRsaSsaPkcs1PublicKeyStruct::CreateParser())
                .AddBytesSecretDataField(3, &JwtRsaSsaPkcs1PrivateKeyStruct::d)
                .AddBytesSecretDataField(4, &JwtRsaSsaPkcs1PrivateKeyStruct::p)
                .AddBytesSecretDataField(5, &JwtRsaSsaPkcs1PrivateKeyStruct::q)
                .AddBytesSecretDataField(6, &JwtRsaSsaPkcs1PrivateKeyStruct::dp)
                .AddBytesSecretDataField(7, &JwtRsaSsaPkcs1PrivateKeyStruct::dq)
                .AddBytesSecretDataField(8,
                                         &JwtRsaSsaPkcs1PrivateKeyStruct::crt)
                .BuildOrDie()};
    return *parser;
  }
};

struct JwtRsaSsaPkcs1KeyFormatStruct {
  uint32_t version;
  JwtRsaSsaPkcs1Algorithm algorithm;
  uint32_t modulus_size_in_bits;
  std::string public_exponent;

  static const ProtoParser<JwtRsaSsaPkcs1KeyFormatStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<JwtRsaSsaPkcs1KeyFormatStruct>>
        parser{ProtoParserBuilder<JwtRsaSsaPkcs1KeyFormatStruct>()
                   .AddUint32Field(1, &JwtRsaSsaPkcs1KeyFormatStruct::version)
                   .AddEnumField(2, &JwtRsaSsaPkcs1KeyFormatStruct::algorithm,
                                 &JwtRsaSsaPkcs1AlgorithmValid)
                   .AddUint32Field(
                       3, &JwtRsaSsaPkcs1KeyFormatStruct::modulus_size_in_bits)
                   .AddBytesStringField(
                       4, &JwtRsaSsaPkcs1KeyFormatStruct::public_exponent)
                   .BuildOrDie()};
    return *parser;
  }
};

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

util::StatusOr<JwtRsaSsaPkcs1Parameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing JwtRsaSsaPkcs1Parameters.");
  }

  util::StatusOr<JwtRsaSsaPkcs1KeyFormatStruct> key_format_struct =
      JwtRsaSsaPkcs1KeyFormatStruct::GetParser().Parse(
          serialization.GetKeyTemplate().value());
  if (!key_format_struct.ok()) {
    return key_format_struct.status();
  }
  if (key_format_struct->version != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing JwtRsaSsaPkcs1Parameters failed: only version 0 is accepted.");
  }

  return ToParameters(serialization.GetKeyTemplate().output_prefix_type(),
                      key_format_struct->algorithm,
                      key_format_struct->modulus_size_in_bits,
                      BigInteger(key_format_struct->public_exponent),
                      /*has_custom_kid=*/false);
}

util::StatusOr<JwtRsaSsaPkcs1PublicKey> ToPublicKey(
    const JwtRsaSsaPkcs1PublicKeyStruct& proto_public_key,
    OutputPrefixType output_prefix_type, absl::optional<int> id_requirement) {
  BigInteger modulus(proto_public_key.n);
  int modulus_size_in_bits = modulus.SizeInBytes() * 8;

  util::StatusOr<JwtRsaSsaPkcs1Parameters> parameters = ToParameters(
      output_prefix_type, proto_public_key.algorithm, modulus_size_in_bits,
      BigInteger(proto_public_key.e), proto_public_key.custom_kid.has_value());
  if (!parameters.ok()) {
    return parameters.status();
  }

  JwtRsaSsaPkcs1PublicKey::Builder builder = JwtRsaSsaPkcs1PublicKey::Builder()
                                                 .SetParameters(*parameters)
                                                 .SetModulus(modulus);
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(*id_requirement);
  }
  if (proto_public_key.custom_kid.has_value()) {
    builder.SetCustomKid(proto_public_key.custom_kid.value().value);
  }
  return builder.Build(GetPartialKeyAccess());
}

util::StatusOr<JwtRsaSsaPkcs1PublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing JwtRsaSsaPkcs1PublicKey.");
  }

  util::StatusOr<JwtRsaSsaPkcs1PublicKeyStruct> public_key_struct =
      JwtRsaSsaPkcs1PublicKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(
              InsecureSecretKeyAccess::Get()));
  if (!public_key_struct.ok()) {
    return public_key_struct.status();
  }
  if (public_key_struct->version != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing JwtRsaSsaPkcs1PublicKey failed: only version 0 is accepted.");
  }
  return ToPublicKey(*public_key_struct, serialization.GetOutputPrefixType(),
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

  util::StatusOr<JwtRsaSsaPkcs1PrivateKeyStruct> private_key_struct =
      JwtRsaSsaPkcs1PrivateKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!private_key_struct.ok()) {
    return private_key_struct.status();
  }
  if (private_key_struct->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }
  if (private_key_struct->public_key.version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 public keys are accepted.");
  }

  util::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key = ToPublicKey(
      private_key_struct->public_key, serialization.GetOutputPrefixType(),
      serialization.IdRequirement());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return JwtRsaSsaPkcs1PrivateKey::Builder()
      .SetPublicKey(*public_key)
      .SetPrimeP(RestrictedBigInteger(private_key_struct->p, *token))
      .SetPrimeQ(RestrictedBigInteger(private_key_struct->q, *token))
      .SetPrimeExponentP(RestrictedBigInteger(private_key_struct->dp, *token))
      .SetPrimeExponentQ(RestrictedBigInteger(private_key_struct->dq, *token))
      .SetPrivateExponent(RestrictedBigInteger(private_key_struct->d, *token))
      .SetCrtCoefficient(RestrictedBigInteger(private_key_struct->crt, *token))
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

  JwtRsaSsaPkcs1KeyFormatStruct key_format{
      /*version=*/0,
      /*algorithm=*/*proto_algorithm,
      /*modulus_size_in_bits=*/
      static_cast<uint32_t>(parameters.GetModulusSizeInBits()),
      /*public_exponent=*/
      std::string(parameters.GetPublicExponent().GetValue()),
  };

  util::StatusOr<std::string> serialized_key_format =
      JwtRsaSsaPkcs1KeyFormatStruct::GetParser().SerializeIntoString(
          key_format);
  if (!serialized_key_format.ok()) {
    return serialized_key_format.status();
  }

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, *serialized_key_format);
}

util::StatusOr<JwtRsaSsaPkcs1PublicKeyStruct> ToStruct(
    const JwtRsaSsaPkcs1PublicKey& public_key) {
  util::StatusOr<JwtRsaSsaPkcs1Algorithm> proto_algorithm =
      ToProtoAlgorithm(public_key.GetParameters().GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }
  JwtRsaSsaPkcs1PublicKeyStruct public_key_struct;
  public_key_struct.version = 0;
  public_key_struct.algorithm = *proto_algorithm;
  public_key_struct.n =
      std::string(public_key.GetModulus(GetPartialKeyAccess()).GetValue());
  public_key_struct.e =
      std::string(public_key.GetParameters().GetPublicExponent().GetValue());
  if (public_key.GetParameters().GetKidStrategy() ==
      JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    public_key_struct.custom_kid = CustomKidStruct{public_key.GetKid().value()};
  }
  return public_key_struct;
}

util::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const JwtRsaSsaPkcs1PublicKey& public_key,
    absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<JwtRsaSsaPkcs1PublicKeyStruct> public_key_struct =
      ToStruct(public_key);
  if (!public_key_struct.ok()) {
    return public_key_struct.status();
  }

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(public_key.GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<std::string> serialized_public_key =
      JwtRsaSsaPkcs1PublicKeyStruct::GetParser().SerializeIntoString(
          *public_key_struct);
  if (!serialized_public_key.ok()) {
    return serialized_public_key.status();
  }

  RestrictedData restricted_output =
      RestrictedData(*serialized_public_key, InsecureSecretKeyAccess::Get());
  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl, std::move(restricted_output), KeyData::ASYMMETRIC_PUBLIC,
      *output_prefix_type, public_key.GetIdRequirement());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePrivateKey(
    const JwtRsaSsaPkcs1PrivateKey& private_key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  util::StatusOr<JwtRsaSsaPkcs1PublicKeyStruct> public_key_struct =
      ToStruct(private_key.GetPublicKey());
  if (!public_key_struct.ok()) {
    return public_key_struct.status();
  }

  JwtRsaSsaPkcs1PrivateKeyStruct private_key_struct;
  private_key_struct.version = 0;
  private_key_struct.public_key = *std::move(public_key_struct);
  private_key_struct.p =
      private_key.GetPrimeP(GetPartialKeyAccess()).GetSecretData(*token);
  private_key_struct.q =
      private_key.GetPrimeQ(GetPartialKeyAccess()).GetSecretData(*token);
  private_key_struct.dp = private_key.GetPrimeExponentP().GetSecretData(*token);
  private_key_struct.dq = private_key.GetPrimeExponentQ().GetSecretData(*token);
  private_key_struct.d = private_key.GetPrivateExponent().GetSecretData(*token);
  private_key_struct.crt =
      private_key.GetCrtCoefficient().GetSecretData(*token);

  util::StatusOr<OutputPrefixType> output_prefix_type = ToOutputPrefixType(
      private_key.GetPublicKey().GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<SecretData> serialized_key =
      JwtRsaSsaPkcs1PrivateKeyStruct::GetParser().SerializeIntoSecretData(
          private_key_struct);
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*std::move(serialized_key), *token);
  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl, std::move(restricted_output),
      KeyData::ASYMMETRIC_PRIVATE, *output_prefix_type,
      private_key.GetIdRequirement());
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
