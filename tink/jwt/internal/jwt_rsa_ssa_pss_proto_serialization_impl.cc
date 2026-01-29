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

#include "tink/jwt/internal/jwt_rsa_ssa_pss_proto_serialization_impl.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
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
#include "tink/internal/proto_parser_enum_field.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_secret_data_field.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/internal/util.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pss_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::BytesField;
using ::crypto::tink::internal::proto_parsing::EnumField;
using ::crypto::tink::internal::proto_parsing::Field;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageField;
using ::crypto::tink::internal::proto_parsing::SecretDataField;
using ::crypto::tink::internal::proto_parsing::Uint32Field;
using ::crypto::tink::util::SecretDataAsStringView;

using JwtRsaSsaPssProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, JwtRsaSsaPssParameters>;
using JwtRsaSsaPssProtoParametersSerializerImpl =
    ParametersSerializerImpl<JwtRsaSsaPssParameters,
                             ProtoParametersSerialization>;
using JwtRsaSsaPssProtoPublicKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, JwtRsaSsaPssPublicKey>;
using JwtRsaSsaPssProtoPublicKeySerializerImpl =
    KeySerializerImpl<JwtRsaSsaPssPublicKey, ProtoKeySerialization>;
using JwtRsaSsaPssProtoPrivateKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, JwtRsaSsaPssPrivateKey>;
using JwtRsaSsaPssProtoPrivateKeySerializerImpl =
    KeySerializerImpl<JwtRsaSsaPssPrivateKey, ProtoKeySerialization>;

class CustomKidTP : public Message {
 public:
  CustomKidTP() = default;
  using Message::SerializeAsString;

  const std::string& value() const { return value_.value(); }
  std::string* mutable_value() { return value_.mutable_value(); }

 private:
  size_t num_fields() const override { return 1; }
  const Field* field(int i) const override {
    return std::array<const Field*, 1>{&value_}[i];
  }

  BytesField value_{1};
};

bool JwtRsaSsaPssAlgorithmValid(int value) { return value >= 0 && value <= 3; }

enum class JwtRsaSsaPssAlgorithmEnum : uint8_t {
  kUnknown = 0,
  kPs256 = 1,
  kPs384 = 2,
  kPs512 = 3,
};

class JwtRsaSsaPssPublicKeyTP : public Message {
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

 private:
  size_t num_fields() const override { return 5; }
  const Field* field(int i) const override {
    return std::array<const Field*, 5>{&version_, &algorithm_, &n_, &e_,
                                       &custom_kid_}[i];
  }

  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  EnumField<JwtRsaSsaPssAlgorithmEnum> algorithm_{2,
                                                  &JwtRsaSsaPssAlgorithmValid};
  BytesField n_{3};
  BytesField e_{4};
  MessageField<CustomKidTP> custom_kid_{5};
};

class JwtRsaSsaPssPrivateKeyTP : public Message {
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

 private:
  size_t num_fields() const override { return 8; }
  const Field* field(int i) const override {
    return std::array<const Field*, 8>{&version_, &public_key_, &d_,  &p_,
                                       &q_,       &dp_,         &dq_, &crt_}[i];
  }

  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  MessageField<JwtRsaSsaPssPublicKeyTP> public_key_{2};
  SecretDataField d_{3};
  SecretDataField p_{4};
  SecretDataField q_{5};
  SecretDataField dp_{6};
  SecretDataField dq_{7};
  SecretDataField crt_{8};
};

class JwtRsaSsaPssKeyFormatTP : public Message {
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

 private:
  size_t num_fields() const override { return 4; }
  const Field* field(int i) const override {
    return std::array<const Field*, 4>{
        &version_, &algorithm_, &modulus_size_in_bits_, &public_exponent_}[i];
  }

  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  EnumField<JwtRsaSsaPssAlgorithmEnum> algorithm_{2,
                                                  &JwtRsaSsaPssAlgorithmValid};
  Uint32Field modulus_size_in_bits_{3, ProtoFieldOptions::kImplicit};
  BytesField public_exponent_{4};
};

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey";

absl::StatusOr<JwtRsaSsaPssParameters::KidStrategy> ToKidStrategy(
    OutputPrefixTypeEnum output_prefix_type, bool has_custom_kid) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kRaw:
      if (has_custom_kid) {
        return JwtRsaSsaPssParameters::KidStrategy::kCustom;
      }
      return JwtRsaSsaPssParameters::KidStrategy::kIgnored;
    case OutputPrefixTypeEnum::kTink:
      return JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId;
    default:
      return absl::InvalidArgumentError(
          "Invalid OutputPrefixType for JwtRsaSsaPssKeyFormat.");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    JwtRsaSsaPssParameters::KidStrategy kid_strategy) {
  switch (kid_strategy) {
    case JwtRsaSsaPssParameters::KidStrategy::kCustom:
    case JwtRsaSsaPssParameters::KidStrategy::kIgnored:
      return OutputPrefixTypeEnum::kRaw;
    case JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId:
      return OutputPrefixTypeEnum::kTink;
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
    OutputPrefixTypeEnum output_prefix_type,
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
    OutputPrefixTypeEnum output_prefix_type,
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
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateTP& key_template = serialization.GetKeyTemplate();
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
    const ProtoKeySerialization& serialization,
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
    const ProtoKeySerialization& serialization,
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

  RestrictedData p_data =
      internal::CallWithCoreDumpProtection([&]() -> RestrictedData {
        return RestrictedData(
            WithoutLeadingZeros(SecretDataAsStringView(private_key.p())),
            InsecureSecretKeyAccess::Get());
      });

  RestrictedData q_data =
      internal::CallWithCoreDumpProtection([&]() -> RestrictedData {
        return RestrictedData(
            WithoutLeadingZeros(SecretDataAsStringView(private_key.q())),
            InsecureSecretKeyAccess::Get());
      });

  absl::StatusOr<SecretData> dp_data = ParseBigIntToFixedLength(
      SecretDataAsStringView(private_key.dp()), p_data.size());
  if (!dp_data.ok()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Failed to parse dp: expected length ", p_data.size(), ", got ",
        SecretDataAsStringView(private_key.dp()).size()));
  }

  absl::StatusOr<SecretData> dq_data = ParseBigIntToFixedLength(
      SecretDataAsStringView(private_key.dq()), q_data.size());
  if (!dq_data.ok()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Failed to parse dq: expected length ", q_data.size(), ", got ",
        SecretDataAsStringView(private_key.dq()).size()));
  }

  absl::StatusOr<SecretData> crt_data = ParseBigIntToFixedLength(
      SecretDataAsStringView(private_key.crt()), p_data.size());
  if (!crt_data.ok()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Failed to parse crt: expected length ", p_data.size(), ", got ",
        SecretDataAsStringView(private_key.crt()).size()));
  }

  absl::StatusOr<SecretData> d_data = ParseBigIntToFixedLength(
      SecretDataAsStringView(private_key.d()),
      (public_key->GetParameters().GetModulusSizeInBits() + 7) / 8);
  if (!d_data.ok()) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Failed to parse d: expected length ",
        (public_key->GetParameters().GetModulusSizeInBits() + 7) / 8, ", got ",
        SecretDataAsStringView(private_key.d()).size()));
  }

  return JwtRsaSsaPssPrivateKey::Builder()
      .SetPublicKey(*public_key)
      .SetPrimeP(p_data)
      .SetPrimeQ(q_data)
      .SetPrimeExponentP(
          RestrictedData(*dp_data, InsecureSecretKeyAccess::Get()))
      .SetPrimeExponentQ(
          RestrictedData(*dq_data, InsecureSecretKeyAccess::Get()))
      .SetPrivateExponent(
          RestrictedData(*d_data, InsecureSecretKeyAccess::Get()))
      .SetCrtCoefficient(RestrictedData(*crt_data, *token))
      .Build(GetPartialKeyAccess());
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const JwtRsaSsaPssParameters& parameters) {
  if (parameters.GetKidStrategy() ==
      JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    return absl::InvalidArgumentError(
        "Unable to serialize JwtRsaSsaPssParameters::KidStrategy::kCustom.");
  }
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
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

  return ProtoParametersSerialization::Create(
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

absl::StatusOr<ProtoKeySerialization> SerializePublicKey(
    const JwtRsaSsaPssPublicKey& public_key,
    absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<JwtRsaSsaPssPublicKeyTP> public_key_tp =
      ToPublicKeyTP(public_key);
  if (!public_key_tp.ok()) {
    return public_key_tp.status();
  }

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(public_key.GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return ProtoKeySerialization::Create(
      kPublicTypeUrl,
      RestrictedData(public_key_tp->SerializeAsSecretData(),
                     InsecureSecretKeyAccess::Get()),
      KeyMaterialTypeEnum::kAsymmetricPublic, *output_prefix_type,
      public_key.GetIdRequirement());
}

absl::StatusOr<ProtoKeySerialization> SerializePrivateKey(
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
      private_key.GetPrimePData(GetPartialKeyAccess()).Get(*token);
  *private_key_tp.mutable_q() =
      private_key.GetPrimeQData(GetPartialKeyAccess()).Get(*token);
  *private_key_tp.mutable_dp() =
      private_key.GetPrimeExponentPData(GetPartialKeyAccess()).Get(*token);
  *private_key_tp.mutable_dq() =
      private_key.GetPrimeExponentQData(GetPartialKeyAccess()).Get(*token);
  *private_key_tp.mutable_d() =
      private_key.GetPrivateExponentData(GetPartialKeyAccess()).Get(*token);
  *private_key_tp.mutable_crt() =
      private_key.GetCrtCoefficientData(GetPartialKeyAccess()).Get(*token);

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type = ToOutputPrefixType(
      private_key.GetPublicKey().GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return ProtoKeySerialization::Create(
      kPrivateTypeUrl,
      RestrictedData(private_key_tp.SerializeAsSecretData(), *token),
      KeyMaterialTypeEnum::kAsymmetricPrivate, *output_prefix_type,
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

absl::Status RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  if (absl::Status status = registry.RegisterParametersParser(
          &JwtRsaSsaPssProtoParametersParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = registry.RegisterParametersSerializer(
          &JwtRsaSsaPssProtoParametersSerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          registry.RegisterKeyParser(&JwtRsaSsaPssProtoPublicKeyParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = registry.RegisterKeySerializer(
          &JwtRsaSsaPssProtoPublicKeySerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          registry.RegisterKeyParser(&JwtRsaSsaPssProtoPrivateKeyParser());
      !status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(
      &JwtRsaSsaPssProtoPrivateKeySerializer());
}

absl::Status RegisterJwtRsaSsaPssProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  if (absl::Status status = builder.RegisterParametersParser(
          &JwtRsaSsaPssProtoParametersParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = builder.RegisterParametersSerializer(
          &JwtRsaSsaPssProtoParametersSerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          builder.RegisterKeyParser(&JwtRsaSsaPssProtoPublicKeyParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = builder.RegisterKeySerializer(
          &JwtRsaSsaPssProtoPublicKeySerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          builder.RegisterKeyParser(&JwtRsaSsaPssProtoPrivateKeyParser());
      !status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(
      &JwtRsaSsaPssProtoPrivateKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
