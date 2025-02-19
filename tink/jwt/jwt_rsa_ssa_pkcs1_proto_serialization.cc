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
#include "absl/status/statusor.h"
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
#include "tink/internal/tink_proto_structs.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;
using ::crypto::tink::util::SecretData;

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
  return value >= 0 && value <= 3;
}

enum class JwtRsaSsaPkcs1AlgorithmEnum : uint32_t {
  kRsUnknown = 0,
  kRs256 = 1,
  kRs384 = 2,
  kRs512 = 3,
};

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
  JwtRsaSsaPkcs1AlgorithmEnum algorithm;
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
  JwtRsaSsaPkcs1AlgorithmEnum algorithm;
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

absl::StatusOr<JwtRsaSsaPkcs1Parameters::KidStrategy> ToKidStrategy(
    internal::OutputPrefixTypeEnum output_prefix_type, bool has_custom_kid) {
  switch (output_prefix_type) {
    case crypto::tink::internal::OutputPrefixTypeEnum::kRaw:
      if (has_custom_kid) {
        return JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom;
      }
      return JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored;
    case crypto::tink::internal::OutputPrefixTypeEnum::kTink:
      return JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId;
    default:
      return absl::InvalidArgumentError(
          "Invalid OutputPrefixType for JwtRsaSsaPkcs1KeyFormat.");
  }
}

absl::StatusOr<internal::OutputPrefixTypeEnum> ToOutputPrefixType(
    JwtRsaSsaPkcs1Parameters::KidStrategy kid_strategy) {
  switch (kid_strategy) {
    case JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom:
    case JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored:
      return internal::OutputPrefixTypeEnum::kRaw;
    case JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId:
      return internal::OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine JwtRsaSsaPkcs1Parameters::KidStrategy.");
  }
}

absl::StatusOr<JwtRsaSsaPkcs1Parameters::Algorithm> FromProtoAlgorithm(
    JwtRsaSsaPkcs1AlgorithmEnum algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPkcs1AlgorithmEnum::kRs256:
      return JwtRsaSsaPkcs1Parameters::Algorithm::kRs256;
    case JwtRsaSsaPkcs1AlgorithmEnum::kRs384:
      return JwtRsaSsaPkcs1Parameters::Algorithm::kRs384;
    case JwtRsaSsaPkcs1AlgorithmEnum::kRs512:
      return JwtRsaSsaPkcs1Parameters::Algorithm::kRs512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine JwtRsaSsaPkcs1Algorithm.");
  }
}

absl::StatusOr<JwtRsaSsaPkcs1AlgorithmEnum> ToProtoAlgorithm(
    JwtRsaSsaPkcs1Parameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPkcs1Parameters::Algorithm::kRs256:
      return JwtRsaSsaPkcs1AlgorithmEnum::kRs256;
    case JwtRsaSsaPkcs1Parameters::Algorithm::kRs384:
      return JwtRsaSsaPkcs1AlgorithmEnum::kRs384;
    case JwtRsaSsaPkcs1Parameters::Algorithm::kRs512:
      return JwtRsaSsaPkcs1AlgorithmEnum::kRs512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine JwtRsaSsaPkcs1Parameters::Algorithm");
  }
}

absl::StatusOr<JwtRsaSsaPkcs1Parameters> ToParameters(
    internal::OutputPrefixTypeEnum output_prefix_type,
    JwtRsaSsaPkcs1AlgorithmEnum proto_algorithm, int modulus_size_in_bits,
    const BigInteger& public_exponent, bool has_custom_kid) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters::KidStrategy> kid_strategy =
      ToKidStrategy(output_prefix_type, has_custom_kid);
  if (!kid_strategy.ok()) {
    return kid_strategy.status();
  }

  absl::StatusOr<JwtRsaSsaPkcs1Parameters::Algorithm> algorithm =
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

absl::StatusOr<JwtRsaSsaPkcs1Parameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtRsaSsaPkcs1Parameters.");
  }

  absl::StatusOr<JwtRsaSsaPkcs1KeyFormatStruct> key_format_struct =
      JwtRsaSsaPkcs1KeyFormatStruct::GetParser().Parse(
          serialization.GetKeyTemplate().value());
  if (!key_format_struct.ok()) {
    return key_format_struct.status();
  }
  if (key_format_struct->version != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtRsaSsaPkcs1Parameters failed: only version 0 is accepted.");
  }

  return ToParameters(serialization.GetKeyTemplateStruct().output_prefix_type,
                      key_format_struct->algorithm,
                      key_format_struct->modulus_size_in_bits,
                      BigInteger(key_format_struct->public_exponent),
                      /*has_custom_kid=*/false);
}

absl::StatusOr<JwtRsaSsaPkcs1PublicKey> ToPublicKey(
    const JwtRsaSsaPkcs1PublicKeyStruct& proto_public_key,
    internal::OutputPrefixTypeEnum output_prefix_type,
    absl::optional<int> id_requirement) {
  BigInteger modulus(proto_public_key.n);
  int modulus_size_in_bits = modulus.SizeInBytes() * 8;

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters = ToParameters(
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

absl::StatusOr<JwtRsaSsaPkcs1PublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtRsaSsaPkcs1PublicKey.");
  }

  absl::StatusOr<JwtRsaSsaPkcs1PublicKeyStruct> public_key_struct =
      JwtRsaSsaPkcs1PublicKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(
              InsecureSecretKeyAccess::Get()));
  if (!public_key_struct.ok()) {
    return public_key_struct.status();
  }
  if (public_key_struct->version != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtRsaSsaPkcs1PublicKey failed: only version 0 is accepted.");
  }
  return ToPublicKey(*public_key_struct,
                     static_cast<internal::OutputPrefixTypeEnum>(
                         serialization.GetOutputPrefixType()),
                     serialization.IdRequirement());
}

absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtRsaSsaPkcs1PrivateKey.");
  }

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKeyStruct> private_key_struct =
      JwtRsaSsaPkcs1PrivateKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!private_key_struct.ok()) {
    return private_key_struct.status();
  }
  if (private_key_struct->version != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }
  if (private_key_struct->public_key.version != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 public keys are accepted.");
  }

  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
      ToPublicKey(private_key_struct->public_key,
                  static_cast<internal::OutputPrefixTypeEnum>(
                      serialization.GetOutputPrefixType()),
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

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const JwtRsaSsaPkcs1Parameters& parameters) {
  if (parameters.GetKidStrategy() ==
      JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    return absl::InvalidArgumentError(
        "Unable to serialize JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom.");
  }
  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  absl::StatusOr<JwtRsaSsaPkcs1AlgorithmEnum> proto_algorithm =
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

  absl::StatusOr<std::string> serialized_key_format =
      JwtRsaSsaPkcs1KeyFormatStruct::GetParser().SerializeIntoString(
          key_format);
  if (!serialized_key_format.ok()) {
    return serialized_key_format.status();
  }

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, *serialized_key_format);
}

absl::StatusOr<JwtRsaSsaPkcs1PublicKeyStruct> ToStruct(
    const JwtRsaSsaPkcs1PublicKey& public_key) {
  absl::StatusOr<JwtRsaSsaPkcs1AlgorithmEnum> proto_algorithm =
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

absl::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const JwtRsaSsaPkcs1PublicKey& public_key,
    absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<JwtRsaSsaPkcs1PublicKeyStruct> public_key_struct =
      ToStruct(public_key);
  if (!public_key_struct.ok()) {
    return public_key_struct.status();
  }

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(public_key.GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<std::string> serialized_public_key =
      JwtRsaSsaPkcs1PublicKeyStruct::GetParser().SerializeIntoString(
          *public_key_struct);
  if (!serialized_public_key.ok()) {
    return serialized_public_key.status();
  }

  RestrictedData restricted_output =
      RestrictedData(*serialized_public_key, InsecureSecretKeyAccess::Get());
  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl, std::move(restricted_output),
      internal::KeyMaterialTypeEnum::kAsymmetricPublic, *output_prefix_type,
      public_key.GetIdRequirement());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePrivateKey(
    const JwtRsaSsaPkcs1PrivateKey& private_key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  absl::StatusOr<JwtRsaSsaPkcs1PublicKeyStruct> public_key_struct =
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

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(
          private_key.GetPublicKey().GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<SecretData> serialized_key =
      JwtRsaSsaPkcs1PrivateKeyStruct::GetParser().SerializeIntoSecretData(
          private_key_struct);
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*std::move(serialized_key), *token);
  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl, std::move(restricted_output),
      internal::KeyMaterialTypeEnum::kAsymmetricPrivate, *output_prefix_type,
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

absl::Status RegisterJwtRsaSsaPkcs1ProtoSerialization() {
  absl::Status status =
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
