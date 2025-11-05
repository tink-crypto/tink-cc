// Copyright 2023 Google LLC
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

#include "tink/signature/rsa_ssa_pss_proto_serialization.h"

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
#include "tink/internal/common_proto_enums.h"
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
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::proto_parsing::BytesField;
using ::crypto::tink::internal::proto_parsing::EnumField;
using ::crypto::tink::internal::proto_parsing::Field;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageField;
using ::crypto::tink::internal::proto_parsing::SecretDataField;
using ::crypto::tink::internal::proto_parsing::Uint32Field;

class RsaSsaPssParamsTP : public Message<RsaSsaPssParamsTP> {
 public:
  RsaSsaPssParamsTP() = default;
  using Message::SerializeAsString;

  internal::HashTypeEnum sig_hash() const { return sig_hash_.value(); }
  void set_sig_hash(internal::HashTypeEnum sig_hash) {
    sig_hash_.set_value(sig_hash);
  }

  internal::HashTypeEnum mgf1_hash() const { return mgf1_hash_.value(); }
  void set_mgf1_hash(internal::HashTypeEnum mgf1_hash) {
    mgf1_hash_.set_value(mgf1_hash);
  }

  uint32_t salt_length() const { return salt_length_.value(); }
  void set_salt_length(uint32_t salt_length) {
    salt_length_.set_value(salt_length);
  }

  std::array<const Field*, 3> GetFields() const {
    return {&sig_hash_, &mgf1_hash_, &salt_length_};
  }

 private:
  EnumField<internal::HashTypeEnum> sig_hash_{1,
                                              &internal::HashTypeEnumIsValid};
  EnumField<internal::HashTypeEnum> mgf1_hash_{2,
                                               &internal::HashTypeEnumIsValid};
  Uint32Field salt_length_{3};
};

class RsaSsaPssPublicKeyTP : public Message<RsaSsaPssPublicKeyTP> {
 public:
  RsaSsaPssPublicKeyTP() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const RsaSsaPssParamsTP& params() const { return params_.value(); }
  RsaSsaPssParamsTP* mutable_params() { return params_.mutable_value(); }

  const std::string& n() const { return n_.value(); }
  void set_n(absl::string_view n) { n_.set_value(n); }

  const std::string& e() const { return e_.value(); }
  void set_e(absl::string_view e) { e_.set_value(e); }

  std::array<const Field*, 4> GetFields() const {
    return {&version_, &params_, &n_, &e_};
  }

 private:
  Uint32Field version_{1};
  MessageField<RsaSsaPssParamsTP> params_{2};
  BytesField<std::string> n_{3};
  BytesField<std::string> e_{4};
};

class RsaSsaPssPrivateKeyTP : public Message<RsaSsaPssPrivateKeyTP> {
 public:
  RsaSsaPssPrivateKeyTP() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const RsaSsaPssPublicKeyTP& public_key() const { return public_key_.value(); }
  RsaSsaPssPublicKeyTP* mutable_public_key() {
    return public_key_.mutable_value();
  }

  const SecretData& d() const { return d_.value(); }
  void set_d(SecretData d) { *d_.mutable_value() = std::move(d); }

  const SecretData& p() const { return p_.value(); }
  void set_p(SecretData p) { *p_.mutable_value() = std::move(p); }

  const SecretData& q() const { return q_.value(); }
  void set_q(SecretData q) { *q_.mutable_value() = std::move(q); }

  const SecretData& dp() const { return dp_.value(); }
  void set_dp(SecretData dp) { *dp_.mutable_value() = std::move(dp); }

  const SecretData& dq() const { return dq_.value(); }
  void set_dq(SecretData dq) { *dq_.mutable_value() = std::move(dq); }

  const SecretData& crt() const { return crt_.value(); }
  void set_crt(SecretData crt) { *crt_.mutable_value() = std::move(crt); }

  std::array<const Field*, 8> GetFields() const {
    return {&version_, &public_key_, &d_, &p_, &q_, &dp_, &dq_, &crt_};
  }

 private:
  Uint32Field version_{1};
  MessageField<RsaSsaPssPublicKeyTP> public_key_{2};
  SecretDataField d_{3};
  SecretDataField p_{4};
  SecretDataField q_{5};
  SecretDataField dp_{6};
  SecretDataField dq_{7};
  SecretDataField crt_{8};
};

class RsaSsaPssKeyFormatTP : public Message<RsaSsaPssKeyFormatTP> {
 public:
  RsaSsaPssKeyFormatTP() = default;
  using Message::SerializeAsString;

  const RsaSsaPssParamsTP& params() const { return params_.value(); }
  RsaSsaPssParamsTP* mutable_params() { return params_.mutable_value(); }

  uint32_t modulus_size_in_bits() const {
    return modulus_size_in_bits_.value();
  }
  void set_modulus_size_in_bits(uint32_t modulus_size_in_bits) {
    modulus_size_in_bits_.set_value(modulus_size_in_bits);
  }

  const std::string& public_exponent() const {
    return public_exponent_.value();
  }
  void set_public_exponent(absl::string_view public_exponent) {
    public_exponent_.set_value(public_exponent);
  }

  std::array<const Field*, 3> GetFields() const {
    return {&params_, &modulus_size_in_bits_, &public_exponent_};
  }

 private:
  MessageField<RsaSsaPssParamsTP> params_{1};
  Uint32Field modulus_size_in_bits_{2};
  BytesField<std::string> public_exponent_{3};
};

using RsaSsaPssProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   RsaSsaPssParameters>;
using RsaSsaPssProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<RsaSsaPssParameters,
                                       internal::ProtoParametersSerialization>;
using RsaSsaPssProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            RsaSsaPssPublicKey>;
using RsaSsaPssProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<RsaSsaPssPublicKey,
                                internal::ProtoKeySerialization>;
using RsaSsaPssProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            RsaSsaPssPrivateKey>;
using RsaSsaPssProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<RsaSsaPssPrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey";

absl::StatusOr<RsaSsaPssParameters::Variant> ToVariant(
    internal::OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case internal::OutputPrefixTypeEnum::kLegacy:
      return RsaSsaPssParameters::Variant::kLegacy;
    case internal::OutputPrefixTypeEnum::kCrunchy:
      return RsaSsaPssParameters::Variant::kCrunchy;
    case internal::OutputPrefixTypeEnum::kRaw:
      return RsaSsaPssParameters::Variant::kNoPrefix;
    case internal::OutputPrefixTypeEnum::kTink:
      return RsaSsaPssParameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine RsaSsaPssParameters::Variant");
  }
}

absl::StatusOr<internal::OutputPrefixTypeEnum> ToOutputPrefixType(
    RsaSsaPssParameters::Variant variant) {
  switch (variant) {
    case RsaSsaPssParameters::Variant::kLegacy:
      return internal::OutputPrefixTypeEnum::kLegacy;
    case RsaSsaPssParameters::Variant::kCrunchy:
      return internal::OutputPrefixTypeEnum::kCrunchy;
    case RsaSsaPssParameters::Variant::kNoPrefix:
      return internal::OutputPrefixTypeEnum::kRaw;
    case RsaSsaPssParameters::Variant::kTink:
      return internal::OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type.");
  }
}

absl::StatusOr<RsaSsaPssParameters::HashType> ToEnumHashType(
    internal::HashTypeEnum hash_type) {
  switch (hash_type) {
    case internal::HashTypeEnum::kSha256:
      return RsaSsaPssParameters::HashType::kSha256;
    case internal::HashTypeEnum::kSha384:
      return RsaSsaPssParameters::HashType::kSha384;
    case internal::HashTypeEnum::kSha512:
      return RsaSsaPssParameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError("Could not determine HashType");
  }
}

absl::StatusOr<internal::HashTypeEnum> ToProtoHashType(
    RsaSsaPssParameters::HashType hash_type) {
  switch (hash_type) {
    case RsaSsaPssParameters::HashType::kSha256:
      return internal::HashTypeEnum::kSha256;
    case RsaSsaPssParameters::HashType::kSha384:
      return internal::HashTypeEnum::kSha384;
    case RsaSsaPssParameters::HashType::kSha512:
      return internal::HashTypeEnum::kSha512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine RsaSsaPssParameters::HashType");
  }
}

absl::StatusOr<RsaSsaPssParameters> ToParameters(
    internal::OutputPrefixTypeEnum output_prefix_type,
    const RsaSsaPssParamsTP& params, int modulus_size_in_bits,
    const BigInteger& public_exponent) {
  absl::StatusOr<RsaSsaPssParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<RsaSsaPssParameters::HashType> sig_hash_type =
      ToEnumHashType(params.sig_hash());
  if (!sig_hash_type.ok()) {
    return sig_hash_type.status();
  }

  absl::StatusOr<RsaSsaPssParameters::HashType> mgf1_hash_type =
      ToEnumHashType(params.mgf1_hash());
  if (!mgf1_hash_type.ok()) {
    return mgf1_hash_type.status();
  }

  return RsaSsaPssParameters::Builder()
      .SetVariant(*variant)
      .SetSigHashType(*sig_hash_type)
      .SetMgf1HashType(*mgf1_hash_type)
      .SetModulusSizeInBits(modulus_size_in_bits)
      .SetPublicExponent(public_exponent)
      .SetSaltLengthInBytes(params.salt_length())
      .Build();
}

absl::StatusOr<RsaSsaPssParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  const internal::KeyTemplateTP key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing RsaSsaPssParameters.");
  }

  RsaSsaPssKeyFormatTP proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError(
        "Failed to parse RsaSsaPssKeyFormatTP proto");
  }

  return ToParameters(key_template.output_prefix_type(),
                      proto_key_format.params(),
                      proto_key_format.modulus_size_in_bits(),
                      BigInteger(proto_key_format.public_exponent()));
}

absl::StatusOr<RsaSsaPssPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing RsaSsaPssPublicKey.");
  }

  RsaSsaPssPublicKeyTP proto_key;
  if (!proto_key.ParseFromString(serialization.SerializedKeyProto().GetSecret(
          InsecureSecretKeyAccess::Get()))) {
    return absl::InvalidArgumentError(
        "Failed to parse RsaSsaPssPublicKeyTP proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  int modulus_size_in_bits = proto_key.n().size() * 8;
  absl::StatusOr<RsaSsaPssParameters> parameters =
      ToParameters(serialization.GetOutputPrefixTypeEnum(), proto_key.params(),
                   modulus_size_in_bits, BigInteger(proto_key.e()));
  if (!parameters.ok()) {
    return parameters.status();
  }

  return RsaSsaPssPublicKey::Create(*parameters, BigInteger(proto_key.n()),
                                    serialization.IdRequirement(),
                                    GetPartialKeyAccess());
}

absl::StatusOr<RsaSsaPssPrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing RsaSsaPssPrivateKey.");
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  RsaSsaPssPrivateKeyTP proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError(
        "Failed to parse RsaSsaPssPrivateKeyTP proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  if (proto_key.public_key().version() != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 public keys are accepted.");
  }

  int modulus_size_in_bits = proto_key.public_key().n().size() * 8;

  absl::StatusOr<RsaSsaPssParameters> parameters = ToParameters(
      serialization.GetOutputPrefixTypeEnum(), proto_key.public_key().params(),
      modulus_size_in_bits, BigInteger(proto_key.public_key().e()));
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, BigInteger(proto_key.public_key().n()),
      serialization.IdRequirement(), GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return RsaSsaPssPrivateKey::Builder()
      .SetPublicKey(*public_key)
      .SetPrimeP(RestrictedBigInteger(proto_key.p(), *token))
      .SetPrimeQ(RestrictedBigInteger(proto_key.q(), *token))
      .SetPrimeExponentP(RestrictedBigInteger(proto_key.dp(), *token))
      .SetPrimeExponentQ(RestrictedBigInteger(proto_key.dq(), *token))
      .SetPrivateExponent(RestrictedBigInteger(proto_key.d(), *token))
      .SetCrtCoefficient(RestrictedBigInteger(proto_key.crt(), *token))
      .Build(GetPartialKeyAccess());
}

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const RsaSsaPssParameters& parameters) {
  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<internal::HashTypeEnum> sig_hash =
      ToProtoHashType(parameters.GetSigHashType());
  if (!sig_hash.ok()) {
    return sig_hash.status();
  }
  absl::StatusOr<internal::HashTypeEnum> mgf1_hash =
      ToProtoHashType(parameters.GetMgf1HashType());
  if (!mgf1_hash.ok()) {
    return mgf1_hash.status();
  }

  RsaSsaPssKeyFormatTP proto_key_format;
  proto_key_format.set_modulus_size_in_bits(parameters.GetModulusSizeInBits());
  proto_key_format.set_public_exponent(
      parameters.GetPublicExponent().GetValue());
  proto_key_format.mutable_params()->set_sig_hash(*sig_hash);
  proto_key_format.mutable_params()->set_mgf1_hash(*mgf1_hash);
  proto_key_format.mutable_params()->set_salt_length(
      parameters.GetSaltLengthInBytes());

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type,
      proto_key_format.SerializeAsString());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const RsaSsaPssPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<internal::HashTypeEnum> sig_hash =
      ToProtoHashType(key.GetParameters().GetSigHashType());
  if (!sig_hash.ok()) {
    return sig_hash.status();
  }
  absl::StatusOr<internal::HashTypeEnum> mgf1_hash =
      ToProtoHashType(key.GetParameters().GetMgf1HashType());
  if (!mgf1_hash.ok()) {
    return mgf1_hash.status();
  }

  RsaSsaPssPublicKeyTP proto_key;
  proto_key.set_version(0);
  proto_key.mutable_params()->set_sig_hash(*sig_hash);
  proto_key.mutable_params()->set_mgf1_hash(*mgf1_hash);
  proto_key.mutable_params()->set_salt_length(
      key.GetParameters().GetSaltLengthInBytes());
  proto_key.set_n(key.GetModulus(GetPartialKeyAccess()).GetValue());
  proto_key.set_e(key.GetParameters().GetPublicExponent().GetValue());

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  RestrictedData restricted_output = RestrictedData(
      proto_key.SerializeAsString(), InsecureSecretKeyAccess::Get());
  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl, restricted_output,
      internal::KeyMaterialTypeEnum::kAsymmetricPublic, *output_prefix_type,
      key.GetIdRequirement());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePrivateKey(
    const RsaSsaPssPrivateKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  absl::StatusOr<internal::HashTypeEnum> sig_hash =
      ToProtoHashType(key.GetPublicKey().GetParameters().GetSigHashType());
  if (!sig_hash.ok()) {
    return sig_hash.status();
  }
  absl::StatusOr<internal::HashTypeEnum> mgf1_hash =
      ToProtoHashType(key.GetPublicKey().GetParameters().GetMgf1HashType());
  if (!mgf1_hash.ok()) {
    return mgf1_hash.status();
  }

  RsaSsaPssPrivateKeyTP proto_private_key;
  proto_private_key.set_version(0);
  proto_private_key.mutable_public_key()->set_version(0);
  proto_private_key.mutable_public_key()->mutable_params()->set_sig_hash(
      *sig_hash);
  proto_private_key.mutable_public_key()->mutable_params()->set_mgf1_hash(
      *mgf1_hash);
  proto_private_key.mutable_public_key()->mutable_params()->set_salt_length(
      key.GetPublicKey().GetParameters().GetSaltLengthInBytes());
  proto_private_key.mutable_public_key()->set_n(
      key.GetPublicKey().GetModulus(GetPartialKeyAccess()).GetValue());
  proto_private_key.mutable_public_key()->set_e(
      key.GetPublicKey().GetParameters().GetPublicExponent().GetValue());
  // OSS proto library complains if input is not converted to a string.
  proto_private_key.set_p(
      key.GetPrimeP(GetPartialKeyAccess()).GetSecretData(*token));
  proto_private_key.set_q(
      key.GetPrimeQ(GetPartialKeyAccess()).GetSecretData(*token));
  proto_private_key.set_dp(key.GetPrimeExponentP().GetSecretData(*token));
  proto_private_key.set_dq(key.GetPrimeExponentQ().GetSecretData(*token));
  proto_private_key.set_d(key.GetPrivateExponent().GetSecretData(*token));
  proto_private_key.set_crt(key.GetCrtCoefficient().GetSecretData(*token));

  RestrictedData serialized_private_key =
      RestrictedData(proto_private_key.SerializeAsSecretData(), *token);

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl, serialized_private_key,
      internal::KeyMaterialTypeEnum::kAsymmetricPrivate, *output_prefix_type,
      key.GetIdRequirement());
}

RsaSsaPssProtoParametersParserImpl* RsaSsaPssProtoParametersParser() {
  static auto* parser =
      new RsaSsaPssProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return parser;
}

RsaSsaPssProtoParametersSerializerImpl* RsaSsaPssProtoParametersSerializer() {
  static auto* serializer = new RsaSsaPssProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return serializer;
}

RsaSsaPssProtoPublicKeyParserImpl* RsaSsaPssProtoPublicKeyParser() {
  static auto* parser =
      new RsaSsaPssProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return parser;
}

RsaSsaPssProtoPublicKeySerializerImpl* RsaSsaPssProtoPublicKeySerializer() {
  static auto* serializer =
      new RsaSsaPssProtoPublicKeySerializerImpl(SerializePublicKey);
  return serializer;
}

RsaSsaPssProtoPrivateKeyParserImpl* RsaSsaPssProtoPrivateKeyParser() {
  static auto* parser =
      new RsaSsaPssProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return parser;
}

RsaSsaPssProtoPrivateKeySerializerImpl* RsaSsaPssProtoPrivateKeySerializer() {
  static auto* serializer =
      new RsaSsaPssProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return serializer;
}

}  // namespace

absl::Status RegisterRsaSsaPssProtoSerialization() {
  absl::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(RsaSsaPssProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersSerializer(RsaSsaPssProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(RsaSsaPssProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeySerializer(RsaSsaPssProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(RsaSsaPssProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(RsaSsaPssProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
