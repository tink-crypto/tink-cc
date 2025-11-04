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
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/internal/proto_parser_secret_data_field.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pss_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::proto_parsing::EnumOwningField;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageOwningField;
using ::crypto::tink::internal::proto_parsing::MessageOwningFieldWithPresence;
using ::crypto::tink::internal::proto_parsing::OwningBytesField;
using ::crypto::tink::internal::proto_parsing::OwningField;
using ::crypto::tink::internal::proto_parsing::SecretDataField;
using ::crypto::tink::internal::proto_parsing::Uint32OwningField;

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

class CustomKidTP : public Message<CustomKidTP> {
 public:
  CustomKidTP() = default;
  using Message::SerializeAsString;

  const std::string& value() const { return value_.value(); }
  std::string* mutable_value() { return value_.mutable_value(); }

  std::array<const OwningField*, 1> GetFields() const { return {&value_}; }

 private:
  OwningBytesField<std::string> value_{1};
};

bool JwtRsaSsaPssAlgorithmValid(int value) { return value >= 0 && value <= 3; }

enum class JwtRsaSsaPssAlgorithmEnum : uint8_t {
  kUnknown = 0,
  kPs256 = 1,
  kPs384 = 2,
  kPs512 = 3,
};

class JwtRsaSsaPssPublicKeyTP : public Message<JwtRsaSsaPssPublicKeyTP> {
 public:
  JwtRsaSsaPssPublicKeyTP() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  JwtRsaSsaPssAlgorithmEnum algorithm() const { return algorithm_.value(); }
  void set_algorithm(JwtRsaSsaPssAlgorithmEnum algorithm) {
    algorithm_.set_value(algorithm);
  }

  const std::string& n() const { return n_.value(); }
  std::string* mutable_n() { return n_.mutable_value(); }

  const std::string& e() const { return e_.value(); }
  std::string* mutable_e() { return e_.mutable_value(); }

  const CustomKidTP& custom_kid() const { return custom_kid_.value(); }
  CustomKidTP* mutable_custom_kid() { return custom_kid_.mutable_value(); }
  bool has_custom_kid() const { return custom_kid_.has_value(); }

  std::array<const OwningField*, 5> GetFields() const {
    return {&version_, &algorithm_, &n_, &e_, &custom_kid_};
  }

 private:
  Uint32OwningField version_{1};
  EnumOwningField<JwtRsaSsaPssAlgorithmEnum> algorithm_{
      2, &JwtRsaSsaPssAlgorithmValid};
  OwningBytesField<std::string> n_{3};
  OwningBytesField<std::string> e_{4};
  MessageOwningFieldWithPresence<CustomKidTP> custom_kid_{5};
};

class JwtRsaSsaPssPrivateKeyTP : public Message<JwtRsaSsaPssPrivateKeyTP> {
 public:
  JwtRsaSsaPssPrivateKeyTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const JwtRsaSsaPssPublicKeyTP& public_key() const {
    return public_key_.value();
  }
  JwtRsaSsaPssPublicKeyTP* mutable_public_key() {
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

  std::array<const OwningField*, 8> GetFields() const {
    return {&version_, &public_key_, &d_, &p_, &q_, &dp_, &dq_, &crt_};
  }

 private:
  Uint32OwningField version_{1};
  MessageOwningField<JwtRsaSsaPssPublicKeyTP> public_key_{2};
  SecretDataField d_{3};
  SecretDataField p_{4};
  SecretDataField q_{5};
  SecretDataField dp_{6};
  SecretDataField dq_{7};
  SecretDataField crt_{8};
};

class JwtRsaSsaPssKeyFormatTP : public Message<JwtRsaSsaPssKeyFormatTP> {
 public:
  JwtRsaSsaPssKeyFormatTP() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  JwtRsaSsaPssAlgorithmEnum algorithm() const { return algorithm_.value(); }
  void set_algorithm(JwtRsaSsaPssAlgorithmEnum algorithm) {
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

  std::array<const OwningField*, 4> GetFields() const {
    return {&version_, &algorithm_, &modulus_size_in_bits_, &public_exponent_};
  }

 private:
  Uint32OwningField version_{1};
  EnumOwningField<JwtRsaSsaPssAlgorithmEnum> algorithm_{
      2, &JwtRsaSsaPssAlgorithmValid};
  Uint32OwningField modulus_size_in_bits_{3};
  OwningBytesField<std::string> public_exponent_{4};
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
    const JwtRsaSsaPssPublicKeyTP& public_key_tp,
    internal::OutputPrefixTypeEnum output_prefix_type,
    absl::optional<int> id_requirement) {
  BigInteger modulus(public_key_tp.n());
  int modulus_size_in_bits = modulus.SizeInBytes() * 8;

  absl::StatusOr<JwtRsaSsaPssParameters> parameters = ToParameters(
      output_prefix_type, public_key_tp.algorithm(), modulus_size_in_bits,
      BigInteger(public_key_tp.e()), public_key_tp.has_custom_kid());
  if (!parameters.ok()) {
    return parameters.status();
  }

  JwtRsaSsaPssPublicKey::Builder builder = JwtRsaSsaPssPublicKey::Builder()
                                               .SetParameters(*parameters)
                                               .SetModulus(modulus);
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(*id_requirement);
  }
  if (public_key_tp.has_custom_kid()) {
    builder.SetCustomKid(public_key_tp.custom_kid().value());
  }
  return builder.Build(GetPartialKeyAccess());
}

absl::StatusOr<JwtRsaSsaPssParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  const internal::KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtRsaSsaPssParameters.");
  }

  JwtRsaSsaPssKeyFormatTP key_format;
  if (!key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError("Failed to parse JwtRsaSsaPssKeyFormat.");
  }
  if (key_format.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtRsaSsaPssParameters failed: only version 0 is accepted.");
  }

  return ToParameters(key_template.output_prefix_type(), key_format.algorithm(),
                      key_format.modulus_size_in_bits(),
                      BigInteger(key_format.public_exponent()),
                      /*has_custom_kid=*/false);
}

absl::StatusOr<JwtRsaSsaPssPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing JwtRsaSsaPssPublicKey.");
  }

  JwtRsaSsaPssPublicKeyTP public_key;
  if (!public_key.ParseFromString(serialization.SerializedKeyProto().GetSecret(
          InsecureSecretKeyAccess::Get()))) {
    return absl::InvalidArgumentError("Failed to parse JwtRsaSsaPssPublicKey.");
  }
  if (public_key.version() != 0) {
    return absl::InvalidArgumentError(
        "Parsing JwtRsaSsaPssPublicKey failed: only version 0 is accepted.");
  }

  return ToPublicKey(public_key, serialization.GetOutputPrefixTypeEnum(),
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

  JwtRsaSsaPssPrivateKeyTP private_key;
  if (!private_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError(
        "Failed to parse JwtRsaSsaPssPrivateKey.");
  }
  if (private_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }
  if (private_key.public_key().version() != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 public keys are accepted.");
  }

  absl::StatusOr<JwtRsaSsaPssPublicKey> public_key = ToPublicKey(
      private_key.public_key(), serialization.GetOutputPrefixTypeEnum(),
      serialization.IdRequirement());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return JwtRsaSsaPssPrivateKey::Builder()
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

  JwtRsaSsaPssKeyFormatTP key_format;
  key_format.set_version(0);
  key_format.set_algorithm(*proto_algorithm);
  key_format.set_modulus_size_in_bits(
      static_cast<uint32_t>(parameters.GetModulusSizeInBits()));
  *key_format.mutable_public_exponent() =
      parameters.GetPublicExponent().GetValue();

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, key_format.SerializeAsString());
}

absl::StatusOr<JwtRsaSsaPssPublicKeyTP> ToPublicKeyTP(
    const JwtRsaSsaPssPublicKey& public_key) {
  absl::StatusOr<JwtRsaSsaPssAlgorithmEnum> proto_algorithm =
      ToProtoAlgorithm(public_key.GetParameters().GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }
  JwtRsaSsaPssPublicKeyTP public_key_tp;
  public_key_tp.set_version(0);
  public_key_tp.set_algorithm(*proto_algorithm);
  *public_key_tp.mutable_n() =
      public_key.GetModulus(GetPartialKeyAccess()).GetValue();
  *public_key_tp.mutable_e() =
      public_key.GetParameters().GetPublicExponent().GetValue();
  if (public_key.GetParameters().GetKidStrategy() ==
      JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    *public_key_tp.mutable_custom_kid()->mutable_value() =
        public_key.GetKid().value();
  }
  return public_key_tp;
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const JwtRsaSsaPssPublicKey& public_key,
    absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<JwtRsaSsaPssPublicKeyTP> public_key_tp =
      ToPublicKeyTP(public_key);
  if (!public_key_tp.ok()) {
    return public_key_tp.status();
  }

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(public_key.GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl,
      RestrictedData(public_key_tp->SerializeAsSecretData(),
                     InsecureSecretKeyAccess::Get()),
      internal::KeyMaterialTypeEnum::kAsymmetricPublic, *output_prefix_type,
      public_key.GetIdRequirement());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePrivateKey(
    const JwtRsaSsaPssPrivateKey& private_key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  absl::StatusOr<JwtRsaSsaPssPublicKeyTP> public_key_tp =
      ToPublicKeyTP(private_key.GetPublicKey());
  if (!public_key_tp.ok()) {
    return public_key_tp.status();
  }

  JwtRsaSsaPssPrivateKeyTP private_key_tp;
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
