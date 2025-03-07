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
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pss_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"
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

struct CustomKidStruct {
  std::string value;

  static ProtoParser<CustomKidStruct> CreateParser() {
    return ProtoParserBuilder<CustomKidStruct>()
        .AddBytesStringField(1, &CustomKidStruct::value)
        .BuildOrDie();
  }
};

bool JwtRsaSsaPssAlgorithmValid(int value) { return value >= 0 && value <= 3; }

enum class JwtRsaSsaPssAlgorithmEnum : uint8_t {
  kUnknown = 0,
  kPs256 = 1,
  kPs384 = 2,
  kPs512 = 3,
};

struct JwtRsaSsaPssPublicKeyStruct {
  uint32_t version;
  JwtRsaSsaPssAlgorithmEnum algorithm;
  std::string n;
  std::string e;
  std::optional<CustomKidStruct> custom_kid;

  static ProtoParser<JwtRsaSsaPssPublicKeyStruct> CreateParser() {
    return ProtoParserBuilder<JwtRsaSsaPssPublicKeyStruct>()
        .AddUint32Field(1, &JwtRsaSsaPssPublicKeyStruct::version)
        .AddEnumField(2, &JwtRsaSsaPssPublicKeyStruct::algorithm,
                      &JwtRsaSsaPssAlgorithmValid)
        .AddBytesStringField(3, &JwtRsaSsaPssPublicKeyStruct::n)
        .AddBytesStringField(4, &JwtRsaSsaPssPublicKeyStruct::e)
        .AddMessageFieldWithPresence(5,
                                     &JwtRsaSsaPssPublicKeyStruct::custom_kid,
                                     CustomKidStruct::CreateParser())
        .BuildOrDie();
  }

  static const ProtoParser<JwtRsaSsaPssPublicKeyStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<JwtRsaSsaPssPublicKeyStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

struct JwtRsaSsaPssPrivateKeyStruct {
  uint32_t version;
  JwtRsaSsaPssPublicKeyStruct public_key;
  SecretData d;
  SecretData p;
  SecretData q;
  SecretData dp;
  SecretData dq;
  SecretData crt;

  static const ProtoParser<JwtRsaSsaPssPrivateKeyStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<JwtRsaSsaPssPrivateKeyStruct>> parser{
        ProtoParserBuilder<JwtRsaSsaPssPrivateKeyStruct>()
            .AddUint32Field(1, &JwtRsaSsaPssPrivateKeyStruct::version)
            .AddMessageField(2, &JwtRsaSsaPssPrivateKeyStruct::public_key,
                             JwtRsaSsaPssPublicKeyStruct::CreateParser())
            .AddBytesSecretDataField(3, &JwtRsaSsaPssPrivateKeyStruct::d)
            .AddBytesSecretDataField(4, &JwtRsaSsaPssPrivateKeyStruct::p)
            .AddBytesSecretDataField(5, &JwtRsaSsaPssPrivateKeyStruct::q)
            .AddBytesSecretDataField(6, &JwtRsaSsaPssPrivateKeyStruct::dp)
            .AddBytesSecretDataField(7, &JwtRsaSsaPssPrivateKeyStruct::dq)
            .AddBytesSecretDataField(8, &JwtRsaSsaPssPrivateKeyStruct::crt)
            .BuildOrDie()};
    return *parser;
  }
};

struct JwtRsaSsaPssKeyFormatStruct {
  uint32_t version;
  JwtRsaSsaPssAlgorithmEnum algorithm;
  uint32_t modulus_size_in_bits;
  std::string public_exponent;

  static const ProtoParser<JwtRsaSsaPssKeyFormatStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<JwtRsaSsaPssKeyFormatStruct>> parser{
        ProtoParserBuilder<JwtRsaSsaPssKeyFormatStruct>()
            .AddUint32Field(1, &JwtRsaSsaPssKeyFormatStruct::version)
            .AddEnumField(2, &JwtRsaSsaPssKeyFormatStruct::algorithm,
                          &JwtRsaSsaPssAlgorithmValid)
            .AddUint32Field(3,
                            &JwtRsaSsaPssKeyFormatStruct::modulus_size_in_bits)
            .AddBytesStringField(4,
                                 &JwtRsaSsaPssKeyFormatStruct::public_exponent)
            .BuildOrDie()};
    return *parser;
  }
};

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey";

absl::StatusOr<JwtRsaSsaPssParameters::KidStrategy> ToKidStrategy(
    internal::OutputPrefixTypeEnum output_prefix_type, bool has_custom_kid) {
  switch (output_prefix_type) {
    case internal::OutputPrefixTypeEnum::kRaw:
      if (has_custom_kid) {
        return JwtRsaSsaPssParameters::KidStrategy::kCustom;
      }
      return JwtRsaSsaPssParameters::KidStrategy::kIgnored;
    case internal::OutputPrefixTypeEnum::kTink:
      return JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId;
    default:
      return absl::InvalidArgumentError(
          "Invalid OutputPrefixType for JwtRsaSsaPssKeyFormat.");
  }
}

absl::StatusOr<internal::OutputPrefixTypeEnum> ToOutputPrefixType(
    JwtRsaSsaPssParameters::KidStrategy kid_strategy) {
  switch (kid_strategy) {
    case JwtRsaSsaPssParameters::KidStrategy::kCustom:
    case JwtRsaSsaPssParameters::KidStrategy::kIgnored:
      return internal::OutputPrefixTypeEnum::kRaw;
    case JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId:
      return internal::OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine JwtRsaSsaPssParameters::KidStrategy.");
  }
}

absl::StatusOr<JwtRsaSsaPssParameters::Algorithm> FromProtoAlgorithm(
    JwtRsaSsaPssAlgorithmEnum algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPssAlgorithmEnum::kPs256:
      return JwtRsaSsaPssParameters::Algorithm::kPs256;
    case JwtRsaSsaPssAlgorithmEnum::kPs384:
      return JwtRsaSsaPssParameters::Algorithm::kPs384;
    case JwtRsaSsaPssAlgorithmEnum::kPs512:
      return JwtRsaSsaPssParameters::Algorithm::kPs512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine JwtRsaSsaPssAlgorithm.");
  }
}

absl::StatusOr<JwtRsaSsaPssAlgorithmEnum> ToProtoAlgorithm(
    JwtRsaSsaPssParameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPssParameters::Algorithm::kPs256:
      return JwtRsaSsaPssAlgorithmEnum::kPs256;
    case JwtRsaSsaPssParameters::Algorithm::kPs384:
      return JwtRsaSsaPssAlgorithmEnum::kPs384;
    case JwtRsaSsaPssParameters::Algorithm::kPs512:
      return JwtRsaSsaPssAlgorithmEnum::kPs512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine JwtRsaSsaPssParameters::Algorithm");
  }
}

absl::StatusOr<JwtRsaSsaPssParameters> ToParameters(
    internal::OutputPrefixTypeEnum output_prefix_type,
    JwtRsaSsaPssAlgorithmEnum proto_algorithm, int modulus_size_in_bits,
    const BigInteger& public_exponent, bool has_custom_kid) {
  absl::StatusOr<JwtRsaSsaPssParameters::KidStrategy> kid_strategy =
      ToKidStrategy(output_prefix_type, has_custom_kid);
  if (!kid_strategy.ok()) {
    return kid_strategy.status();
  }

  absl::StatusOr<JwtRsaSsaPssParameters::Algorithm> algorithm =
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

absl::StatusOr<JwtRsaSsaPssPublicKey> ToPublicKey(
    const JwtRsaSsaPssPublicKeyStruct& public_key_struct,
    internal::OutputPrefixTypeEnum output_prefix_type,
    absl::optional<int> id_requirement) {
  BigInteger modulus(public_key_struct.n);
  int modulus_size_in_bits = modulus.SizeInBytes() * 8;

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      ToParameters(output_prefix_type, public_key_struct.algorithm,
                   modulus_size_in_bits, BigInteger(public_key_struct.e),
                   public_key_struct.custom_kid.has_value());
  if (!parameters.ok()) {
    return parameters.status();
  }

  JwtRsaSsaPssPublicKey::Builder builder = JwtRsaSsaPssPublicKey::Builder()
                                               .SetParameters(*parameters)
                                               .SetModulus(modulus);
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(*id_requirement);
  }
  if (public_key_struct.custom_kid.has_value()) {
    builder.SetCustomKid(public_key_struct.custom_kid.value().value);
  }
  return builder.Build(GetPartialKeyAccess());
}

absl::StatusOr<JwtRsaSsaPssParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  const internal::KeyTemplateStruct& key_template =
      serialization.GetKeyTemplateStruct();
  if (key_template.type_url != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtRsaSsaPssParameters.");
  }

  absl::StatusOr<JwtRsaSsaPssKeyFormatStruct> key_format_struct =
      JwtRsaSsaPssKeyFormatStruct::GetParser().Parse(key_template.value);
  if (!key_format_struct.ok()) {
    return key_format_struct.status();
  }
  if (key_format_struct->version != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtRsaSsaPssParameters failed: only version 0 is accepted.");
  }

  return ToParameters(serialization.GetKeyTemplateStruct().output_prefix_type,
                      key_format_struct->algorithm,
                      key_format_struct->modulus_size_in_bits,
                      BigInteger(key_format_struct->public_exponent),
                      /*has_custom_kid=*/false);
}

absl::StatusOr<JwtRsaSsaPssPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtRsaSsaPssPublicKey.");
  }

  absl::StatusOr<JwtRsaSsaPssPublicKeyStruct> public_key_struct =
      JwtRsaSsaPssPublicKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(
              InsecureSecretKeyAccess::Get()));
  if (!public_key_struct.ok()) {
    return public_key_struct.status();
  }
  if (public_key_struct->version != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtRsaSsaPssPublicKey failed: only version 0 is accepted.");
  }

  return ToPublicKey(*public_key_struct,
                     serialization.GetOutputPrefixTypeEnum(),
                     serialization.IdRequirement());
}

absl::StatusOr<JwtRsaSsaPssPrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtRsaSsaPssPrivateKey.");
  }

  absl::StatusOr<JwtRsaSsaPssPrivateKeyStruct> private_key_struct =
      JwtRsaSsaPssPrivateKeyStruct::GetParser().Parse(
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

  absl::StatusOr<JwtRsaSsaPssPublicKey> public_key = ToPublicKey(
      private_key_struct->public_key, serialization.GetOutputPrefixTypeEnum(),
      serialization.IdRequirement());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return JwtRsaSsaPssPrivateKey::Builder()
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
    const JwtRsaSsaPssParameters& parameters) {
  if (parameters.GetKidStrategy() ==
      JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    return absl::InvalidArgumentError(
        "Unable to serialize JwtRsaSsaPssParameters::KidStrategy::kCustom.");
  }
  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  absl::StatusOr<JwtRsaSsaPssAlgorithmEnum> proto_algorithm =
      ToProtoAlgorithm(parameters.GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  JwtRsaSsaPssKeyFormatStruct key_format;
  key_format.version = 0;
  key_format.algorithm = *proto_algorithm;
  key_format.modulus_size_in_bits =
      static_cast<uint32_t>(parameters.GetModulusSizeInBits());
  key_format.public_exponent =
      std::string(parameters.GetPublicExponent().GetValue());

  absl::StatusOr<std::string> serialized_key_format =
      JwtRsaSsaPssKeyFormatStruct::GetParser().SerializeIntoString(key_format);
  if (!serialized_key_format.ok()) {
    return serialized_key_format.status();
  }

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, *serialized_key_format);
}

absl::StatusOr<JwtRsaSsaPssPublicKeyStruct> ToStruct(
    const JwtRsaSsaPssPublicKey& public_key) {
  absl::StatusOr<JwtRsaSsaPssAlgorithmEnum> proto_algorithm =
      ToProtoAlgorithm(public_key.GetParameters().GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }
  JwtRsaSsaPssPublicKeyStruct public_key_struct;
  public_key_struct.version = 0;
  public_key_struct.algorithm = *proto_algorithm;
  public_key_struct.n =
      std::string(public_key.GetModulus(GetPartialKeyAccess()).GetValue());
  public_key_struct.e =
      std::string(public_key.GetParameters().GetPublicExponent().GetValue());
  if (public_key.GetParameters().GetKidStrategy() ==
      JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    public_key_struct.custom_kid = CustomKidStruct{public_key.GetKid().value()};
  }
  return public_key_struct;
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const JwtRsaSsaPssPublicKey& public_key,
    absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<JwtRsaSsaPssPublicKeyStruct> public_key_struct =
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
      JwtRsaSsaPssPublicKeyStruct::GetParser().SerializeIntoString(
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
    const JwtRsaSsaPssPrivateKey& private_key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  absl::StatusOr<JwtRsaSsaPssPublicKeyStruct> public_key_struct =
      ToStruct(private_key.GetPublicKey());
  if (!public_key_struct.ok()) {
    return public_key_struct.status();
  }

  JwtRsaSsaPssPrivateKeyStruct private_key_struct;
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
      JwtRsaSsaPssPrivateKeyStruct::GetParser().SerializeIntoSecretData(
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
  static auto* parser =
      new JwtRsaSsaPssProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
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

absl::Status RegisterJwtRsaSsaPssProtoSerialization() {
  absl::Status status =
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

  status = internal::MutableSerializationRegistry::GlobalInstance()
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
