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

#include <array>
#include <cstdint>
#include <string>
#include <utility>

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
#include "tink/internal/proto_parser_enum_field.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_secret_data_field.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::proto_parsing::BytesField;
using ::crypto::tink::internal::proto_parsing::EnumField;
using ::crypto::tink::internal::proto_parsing::Field;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageField;
using ::crypto::tink::internal::proto_parsing::MessageFieldWithPresence;
using ::crypto::tink::internal::proto_parsing::SecretDataField;
using ::crypto::tink::internal::proto_parsing::Uint32Field;

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

class CustomKidTP : public Message<CustomKidTP> {
 public:
  CustomKidTP() = default;
  using Message::SerializeAsString;

  const std::string& value() const { return value_.value(); }
  std::string* mutable_value() { return value_.mutable_value(); }

  std::array<const Field*, 1> GetFields() const { return {&value_}; }

 private:
  BytesField<std::string> value_{1};
};

class JwtRsaSsaPkcs1PublicKeyTP : public Message<JwtRsaSsaPkcs1PublicKeyTP> {
 public:
  JwtRsaSsaPkcs1PublicKeyTP() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  JwtRsaSsaPkcs1AlgorithmEnum algorithm() const { return algorithm_.value(); }
  void set_algorithm(JwtRsaSsaPkcs1AlgorithmEnum algorithm) {
    algorithm_.set_value(algorithm);
  }

  const std::string& n() const { return n_.value(); }
  std::string* mutable_n() { return n_.mutable_value(); }

  const std::string& e() const { return e_.value(); }
  std::string* mutable_e() { return e_.mutable_value(); }

  const CustomKidTP& custom_kid() const { return custom_kid_.value(); }
  CustomKidTP* mutable_custom_kid() { return custom_kid_.mutable_value(); }
  bool has_custom_kid() const { return custom_kid_.has_value(); }

  std::array<const Field*, 5> GetFields() const {
    return {&version_, &algorithm_, &n_, &e_, &custom_kid_};
  }

 private:
  Uint32Field version_{1};
  EnumField<JwtRsaSsaPkcs1AlgorithmEnum> algorithm_{
      2, &JwtRsaSsaPkcs1AlgorithmValid};
  BytesField<std::string> n_{3};
  BytesField<std::string> e_{4};
  MessageFieldWithPresence<CustomKidTP> custom_kid_{5};
};

class JwtRsaSsaPkcs1PrivateKeyTP : public Message<JwtRsaSsaPkcs1PrivateKeyTP> {
 public:
  JwtRsaSsaPkcs1PrivateKeyTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const JwtRsaSsaPkcs1PublicKeyTP& public_key() const {
    return public_key_.value();
  }
  JwtRsaSsaPkcs1PublicKeyTP* mutable_public_key() {
    return public_key_.mutable_value();
  }

  const SecretData& d() const { return d_.value(); }
  SecretData* mutable_d() { return d_.mutable_value(); }

  const SecretData& p() const { return p_.value(); }
  SecretData* mutable_p() { return p_.mutable_value(); }

  const SecretData& q() const { return q_.value(); }
  SecretData* mutable_q() { return q_.mutable_value(); }

  const SecretData& dp() const { return dp_.value(); }
  SecretData* mutable_dp() { return dp_.mutable_value(); }

  const SecretData& dq() const { return dq_.value(); }
  SecretData* mutable_dq() { return dq_.mutable_value(); }

  const SecretData& crt() const { return crt_.value(); }
  SecretData* mutable_crt() { return crt_.mutable_value(); }

  std::array<const Field*, 8> GetFields() const {
    return {&version_, &public_key_, &d_, &p_, &q_, &dp_, &dq_, &crt_};
  }

 private:
  Uint32Field version_{1};
  MessageField<JwtRsaSsaPkcs1PublicKeyTP> public_key_{2};
  SecretDataField d_{3};
  SecretDataField p_{4};
  SecretDataField q_{5};
  SecretDataField dp_{6};
  SecretDataField dq_{7};
  SecretDataField crt_{8};
};

class JwtRsaSsaPkcs1KeyFormatTP : public Message<JwtRsaSsaPkcs1KeyFormatTP> {
 public:
  JwtRsaSsaPkcs1KeyFormatTP() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  JwtRsaSsaPkcs1AlgorithmEnum algorithm() const { return algorithm_.value(); }
  void set_algorithm(JwtRsaSsaPkcs1AlgorithmEnum algorithm) {
    algorithm_.set_value(algorithm);
  }

  uint32_t modulus_size_in_bits() const {
    return modulus_size_in_bits_.value();
  }
  void set_modulus_size_in_bits(uint32_t modulus_size_in_bits) {
    modulus_size_in_bits_.set_value(modulus_size_in_bits);
  }

  const std::string& public_exponent() const {
    return public_exponent_.value();
  }
  std::string* mutable_public_exponent() {
    return public_exponent_.mutable_value();
  }

  std::array<const Field*, 4> GetFields() const {
    return {&version_, &algorithm_, &modulus_size_in_bits_, &public_exponent_};
  }

 private:
  Uint32Field version_{1};
  EnumField<JwtRsaSsaPkcs1AlgorithmEnum> algorithm_{
      2, &JwtRsaSsaPkcs1AlgorithmValid};
  Uint32Field modulus_size_in_bits_{3};
  BytesField<std::string> public_exponent_{4};
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
  const internal::KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtRsaSsaPkcs1Parameters.");
  }

  JwtRsaSsaPkcs1KeyFormatTP key_format;
  if (!key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError(
        "Failed to parse JwtRsaSsaPkcs1KeyFormat.");
  }
  if (key_format.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtRsaSsaPkcs1Parameters failed: only version 0 is accepted.");
  }

  return ToParameters(key_template.output_prefix_type(), key_format.algorithm(),
                      key_format.modulus_size_in_bits(),
                      BigInteger(key_format.public_exponent()),
                      /*has_custom_kid=*/false);
}

absl::StatusOr<JwtRsaSsaPkcs1PublicKey> ToPublicKey(
    const JwtRsaSsaPkcs1PublicKeyTP& proto_public_key,
    internal::OutputPrefixTypeEnum output_prefix_type,
    absl::optional<int> id_requirement) {
  BigInteger modulus(proto_public_key.n());
  int modulus_size_in_bits = modulus.SizeInBytes() * 8;

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters = ToParameters(
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

absl::StatusOr<JwtRsaSsaPkcs1PublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtRsaSsaPkcs1PublicKey.");
  }

  JwtRsaSsaPkcs1PublicKeyTP public_key;
  if (!public_key.ParseFromString(serialization.SerializedKeyProto().GetSecret(
          InsecureSecretKeyAccess::Get()))) {
    return absl::InvalidArgumentError(
        "Failed to parse JwtRsaSsaPkcs1PublicKey.");
  }
  if (public_key.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtRsaSsaPkcs1PublicKey failed: only version 0 is accepted.");
  }
  return ToPublicKey(public_key, serialization.GetOutputPrefixTypeEnum(),
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

  JwtRsaSsaPkcs1PrivateKeyTP private_key;
  if (!private_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError(
        "Failed to parse JwtRsaSsaPkcs1PrivateKey.");
  }
  if (private_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }
  if (private_key.public_key().version() != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 public keys are accepted.");
  }

  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key = ToPublicKey(
      private_key.public_key(), serialization.GetOutputPrefixTypeEnum(),
      serialization.IdRequirement());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return JwtRsaSsaPkcs1PrivateKey::Builder()
      .SetPublicKey(*public_key)
      .SetPrimeP(RestrictedBigInteger(private_key.p(), *token))
      .SetPrimeQ(RestrictedBigInteger(private_key.q(), *token))
      .SetPrimeExponentP(RestrictedBigInteger(private_key.dp(), *token))
      .SetPrimeExponentQ(RestrictedBigInteger(private_key.dq(), *token))
      .SetPrivateExponent(RestrictedBigInteger(private_key.d(), *token))
      .SetCrtCoefficient(RestrictedBigInteger(private_key.crt(), *token))
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

  JwtRsaSsaPkcs1KeyFormatTP key_format;
  key_format.set_version(0);
  key_format.set_algorithm(*proto_algorithm);
  key_format.set_modulus_size_in_bits(parameters.GetModulusSizeInBits());
  *key_format.mutable_public_exponent() =
      parameters.GetPublicExponent().GetValue();

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, key_format.SerializeAsString());
}

absl::StatusOr<JwtRsaSsaPkcs1PublicKeyTP> ToPublicKeyTP(
    const JwtRsaSsaPkcs1PublicKey& public_key) {
  absl::StatusOr<JwtRsaSsaPkcs1AlgorithmEnum> proto_algorithm =
      ToProtoAlgorithm(public_key.GetParameters().GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }
  JwtRsaSsaPkcs1PublicKeyTP public_key_tp;
  public_key_tp.set_version(0);
  public_key_tp.set_algorithm(*proto_algorithm);
  *public_key_tp.mutable_n() =
      public_key.GetModulus(GetPartialKeyAccess()).GetValue();
  *public_key_tp.mutable_e() =
      public_key.GetParameters().GetPublicExponent().GetValue();
  if (public_key.GetParameters().GetKidStrategy() ==
      JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    *public_key_tp.mutable_custom_kid()->mutable_value() =
        public_key.GetKid().value();
  }
  return public_key_tp;
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const JwtRsaSsaPkcs1PublicKey& public_key,
    absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<JwtRsaSsaPkcs1PublicKeyTP> public_key_tp =
      ToPublicKeyTP(public_key);
  if (!public_key_tp.ok()) {
    return public_key_tp.status();
  }

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(public_key.GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<std::string> serialized_public_key =
      public_key_tp->SerializeAsString();
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

  absl::StatusOr<JwtRsaSsaPkcs1PublicKeyTP> public_key_tp =
      ToPublicKeyTP(private_key.GetPublicKey());
  if (!public_key_tp.ok()) {
    return public_key_tp.status();
  }

  JwtRsaSsaPkcs1PrivateKeyTP private_key_tp;
  private_key_tp.set_version(0);
  *private_key_tp.mutable_public_key() = *std::move(public_key_tp);
  *private_key_tp.mutable_p() =
      private_key.GetPrimeP(GetPartialKeyAccess()).GetSecretData(*token);
  *private_key_tp.mutable_q() =
      private_key.GetPrimeQ(GetPartialKeyAccess()).GetSecretData(*token);
  *private_key_tp.mutable_dp() =
      private_key.GetPrimeExponentP().GetSecretData(*token);
  *private_key_tp.mutable_dq() =
      private_key.GetPrimeExponentQ().GetSecretData(*token);
  *private_key_tp.mutable_d() =
      private_key.GetPrivateExponent().GetSecretData(*token);
  *private_key_tp.mutable_crt() =
      private_key.GetCrtCoefficient().GetSecretData(*token);

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(
          private_key.GetPublicKey().GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl,
      RestrictedData(private_key_tp.SerializeAsSecretData(), *token),
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
