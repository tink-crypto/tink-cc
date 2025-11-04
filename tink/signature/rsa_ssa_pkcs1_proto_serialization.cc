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

#include "tink/signature/rsa_ssa_pkcs1_proto_serialization.h"

#include <array>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/nullability.h"
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
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/internal/proto_parser_secret_data_owning_field.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/util/secret_data.h"

ABSL_POINTERS_DEFAULT_NONNULL

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::proto_parsing::EnumOwningField;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageOwningField;
using ::crypto::tink::internal::proto_parsing::OwningBytesField;
using ::crypto::tink::internal::proto_parsing::OwningField;
using ::crypto::tink::internal::proto_parsing::SecretDataOwningField;
using ::crypto::tink::internal::proto_parsing::Uint32OwningField;
using ::crypto::tink::util::SecretDataAsStringView;

class RsaSsaPkcs1ParamsTP : public Message<RsaSsaPkcs1ParamsTP> {
 public:
  RsaSsaPkcs1ParamsTP() = default;

  std::array<const OwningField*, 1> GetFields() const { return {&hash_type_}; }

  void set_hash_type(internal::HashTypeEnum hash_type) {
    hash_type_.set_value(hash_type);
  }
  internal::HashTypeEnum hash_type() const { return hash_type_.value(); }

 private:
  EnumOwningField<internal::HashTypeEnum> hash_type_{
      1, internal::HashTypeEnumIsValid};
};

class RsaSsaPkcs1PublicKeyMessageTP final
    : public Message<RsaSsaPkcs1PublicKeyMessageTP> {
 public:
  RsaSsaPkcs1PublicKeyMessageTP() = default;

  std::array<const OwningField*, 4> GetFields() const {
    return {&version_, &params_, &n_, &e_};
  }

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const RsaSsaPkcs1ParamsTP& params() const { return params_.value(); }
  RsaSsaPkcs1ParamsTP* mutable_params() { return params_.mutable_value(); }

  const std::string& n() const { return n_.value(); }
  void set_n(absl::string_view n) { n_.set_value(n); }

  const std::string& e() const { return e_.value(); }
  void set_e(absl::string_view e) { e_.set_value(e); }

 private:
  Uint32OwningField version_{1};
  MessageOwningField<RsaSsaPkcs1ParamsTP> params_{2};
  OwningBytesField<std::string> n_{3};
  OwningBytesField<std::string> e_{4};
};

class RsaSsaPkcs1PrivateKeyTP final : public Message<RsaSsaPkcs1PrivateKeyTP> {
 public:
  RsaSsaPkcs1PrivateKeyTP() = default;

  std::array<const OwningField*, 8> GetFields() const {
    return {&version_, &public_key_, &d_, &p_, &q_, &dp_, &dq_, &crt_};
  }

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const RsaSsaPkcs1PublicKeyMessageTP& public_key() const {
    return public_key_.value();
  }
  RsaSsaPkcs1PublicKeyMessageTP* mutable_public_key() {
    return public_key_.mutable_value();
  }

  const SecretData& d() const { return d_.value(); }
  void set_d(absl::string_view d) {
    *d_.mutable_value() = util::SecretDataFromStringView(d);
  }

  const SecretData& p() const { return p_.value(); }
  void set_p(absl::string_view p) {
    *p_.mutable_value() = util::SecretDataFromStringView(p);
  }

  const SecretData& q() const { return q_.value(); }
  void set_q(absl::string_view q) {
    *q_.mutable_value() = util::SecretDataFromStringView(q);
  }

  const SecretData& dp() const { return dp_.value(); }
  void set_dp(absl::string_view dp) {
    *dp_.mutable_value() = util::SecretDataFromStringView(dp);
  }

  const SecretData& dq() const { return dq_.value(); }
  void set_dq(absl::string_view dq) {
    *dq_.mutable_value() = util::SecretDataFromStringView(dq);
  }

  const SecretData& crt() const { return crt_.value(); }
  void set_crt(absl::string_view crt) {
    *crt_.mutable_value() = util::SecretDataFromStringView(crt);
  }

 private:
  Uint32OwningField version_{1};
  MessageOwningField<RsaSsaPkcs1PublicKeyMessageTP> public_key_{2};
  SecretDataOwningField d_{3};
  SecretDataOwningField p_{4};
  SecretDataOwningField q_{5};
  SecretDataOwningField dp_{6};
  SecretDataOwningField dq_{7};
  SecretDataOwningField crt_{8};
};

class RsaSsaPkcs1KeyFormatTP final : public Message<RsaSsaPkcs1KeyFormatTP> {
 public:
  RsaSsaPkcs1KeyFormatTP() = default;

  std::array<const OwningField*, 3> GetFields() const {
    return {&params_, &modulus_size_in_bits_, &public_exponent_};
  }

  const RsaSsaPkcs1ParamsTP& params() const { return params_.value(); }
  RsaSsaPkcs1ParamsTP* mutable_params() { return params_.mutable_value(); }

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

  using Message::SerializeAsString;

 private:
  MessageOwningField<RsaSsaPkcs1ParamsTP> params_{1};
  Uint32OwningField modulus_size_in_bits_{2};
  OwningBytesField<std::string> public_exponent_{3};
};

using RsaSsaPkcs1ProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   RsaSsaPkcs1Parameters>;
using RsaSsaPkcs1ProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<RsaSsaPkcs1Parameters,
                                       internal::ProtoParametersSerialization>;
using RsaSsaPkcs1ProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            RsaSsaPkcs1PublicKey>;
using RsaSsaPkcs1ProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<RsaSsaPkcs1PublicKey,
                                internal::ProtoKeySerialization>;
using RsaSsaPkcs1ProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            RsaSsaPkcs1PrivateKey>;
using RsaSsaPkcs1ProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<RsaSsaPkcs1PrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey";

absl::StatusOr<RsaSsaPkcs1Parameters::Variant> ToVariant(
    internal::OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case internal::OutputPrefixTypeEnum::kLegacy:
      return RsaSsaPkcs1Parameters::Variant::kLegacy;
    case internal::OutputPrefixTypeEnum::kCrunchy:
      return RsaSsaPkcs1Parameters::Variant::kCrunchy;
    case internal::OutputPrefixTypeEnum::kRaw:
      return RsaSsaPkcs1Parameters::Variant::kNoPrefix;
    case internal::OutputPrefixTypeEnum::kTink:
      return RsaSsaPkcs1Parameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine RsaSsaPkcs1Parameters::Variant");
  }
}

absl::StatusOr<internal::OutputPrefixTypeEnum> ToOutputPrefixType(
    RsaSsaPkcs1Parameters::Variant variant) {
  switch (variant) {
    case RsaSsaPkcs1Parameters::Variant::kLegacy:
      return internal::OutputPrefixTypeEnum::kLegacy;
    case RsaSsaPkcs1Parameters::Variant::kCrunchy:
      return internal::OutputPrefixTypeEnum::kCrunchy;
    case RsaSsaPkcs1Parameters::Variant::kNoPrefix:
      return internal::OutputPrefixTypeEnum::kRaw;
    case RsaSsaPkcs1Parameters::Variant::kTink:
      return internal::OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type.");
  }
}

absl::StatusOr<RsaSsaPkcs1Parameters::HashType> ToEnumHashType(
    internal::HashTypeEnum hash_type) {
  switch (hash_type) {
    case internal::HashTypeEnum::kSha256:
      return RsaSsaPkcs1Parameters::HashType::kSha256;
    case internal::HashTypeEnum::kSha384:
      return RsaSsaPkcs1Parameters::HashType::kSha384;
    case internal::HashTypeEnum::kSha512:
      return RsaSsaPkcs1Parameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError("Could not determine HashType");
  }
}

absl::StatusOr<internal::HashTypeEnum> ToProtoHashType(
    RsaSsaPkcs1Parameters::HashType hash_type) {
  switch (hash_type) {
    case RsaSsaPkcs1Parameters::HashType::kSha256:
      return internal::HashTypeEnum::kSha256;
    case RsaSsaPkcs1Parameters::HashType::kSha384:
      return internal::HashTypeEnum::kSha384;
    case RsaSsaPkcs1Parameters::HashType::kSha512:
      return internal::HashTypeEnum::kSha512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine RsaSsaPkcs1Parameters::HashType");
  }
}

absl::StatusOr<RsaSsaPkcs1Parameters> ToParameters(
    internal::OutputPrefixTypeEnum output_prefix_type,
    const RsaSsaPkcs1ParamsTP& params, int modulus_size_in_bits,
    const BigInteger& public_exponent) {
  absl::StatusOr<RsaSsaPkcs1Parameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<RsaSsaPkcs1Parameters::HashType> hash_type =
      ToEnumHashType(params.hash_type());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  return RsaSsaPkcs1Parameters::Builder()
      .SetVariant(*variant)
      .SetHashType(*hash_type)
      .SetModulusSizeInBits(modulus_size_in_bits)
      .SetPublicExponent(public_exponent)
      .Build();
}

absl::StatusOr<RsaSsaPkcs1Parameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  const internal::KeyTemplateTP key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing RsaSsaPkcs1Parameters.");
  }

  RsaSsaPkcs1KeyFormatTP proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError(
        "Failed to parse RsaSsaPkcs1KeyFormat proto");
  }

  return ToParameters(key_template.output_prefix_type(),
                      proto_key_format.params(),
                      proto_key_format.modulus_size_in_bits(),
                      BigInteger(proto_key_format.public_exponent()));
}

absl::StatusOr<RsaSsaPkcs1PublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing RsaSsaPkcs1PublicKey.");
  }

  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  RsaSsaPkcs1PublicKeyMessageTP proto_key;
  if (!proto_key.ParseFromString(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()))) {
    return absl::InvalidArgumentError(
        "Failed to parse RsaSsaPkcs1PublicKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  BigInteger modulus(proto_key.n());
  int modulus_size_in_bits = modulus.SizeInBytes() * 8;
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      ToParameters(serialization.GetOutputPrefixTypeEnum(), proto_key.params(),
                   modulus_size_in_bits, BigInteger(proto_key.e()));
  if (!parameters.ok()) {
    return parameters.status();
  }

  return RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                      serialization.IdRequirement(),
                                      GetPartialKeyAccess());
}

absl::StatusOr<RsaSsaPkcs1PrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing RsaSsaPkcs1PrivateKey.");
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  RsaSsaPkcs1PrivateKeyTP proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError(
        "Failed to parse RsaSsaPkcs1PrivateKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }
  if (proto_key.public_key().version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  BigInteger modulus(proto_key.public_key().n());
  int modulus_size_in_bits = modulus.SizeInBytes() * 8;

  absl::StatusOr<RsaSsaPkcs1Parameters> parameters = ToParameters(
      serialization.GetOutputPrefixTypeEnum(), proto_key.public_key().params(),
      modulus_size_in_bits, BigInteger(proto_key.public_key().e()));
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   serialization.IdRequirement(),
                                   GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return RsaSsaPkcs1PrivateKey::Builder()
      .SetPublicKey(*public_key)
      .SetPrimeP(
          RestrictedBigInteger(SecretDataAsStringView(proto_key.p()), *token))
      .SetPrimeQ(
          RestrictedBigInteger(SecretDataAsStringView(proto_key.q()), *token))
      .SetPrimeExponentP(
          RestrictedBigInteger(SecretDataAsStringView(proto_key.dp()), *token))
      .SetPrimeExponentQ(
          RestrictedBigInteger(SecretDataAsStringView(proto_key.dq()), *token))
      .SetPrivateExponent(
          RestrictedBigInteger(SecretDataAsStringView(proto_key.d()), *token))
      .SetCrtCoefficient(
          RestrictedBigInteger(SecretDataAsStringView(proto_key.crt()), *token))
      .Build(GetPartialKeyAccess());
}

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const RsaSsaPkcs1Parameters& parameters) {
  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<internal::HashTypeEnum> hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }
  RsaSsaPkcs1KeyFormatTP proto_key_format;
  proto_key_format.mutable_params()->set_hash_type(*hash_type);
  proto_key_format.set_modulus_size_in_bits(parameters.GetModulusSizeInBits());
  proto_key_format.set_public_exponent(
      parameters.GetPublicExponent().GetValue());

  std::string serialized_proto = proto_key_format.SerializeAsString();
  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, serialized_proto);
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const RsaSsaPkcs1PublicKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<internal::HashTypeEnum> hash_type =
      ToProtoHashType(key.GetParameters().GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  RsaSsaPkcs1PublicKeyMessageTP proto_key;
  proto_key.mutable_params()->set_hash_type(*hash_type);
  proto_key.set_version(0);
  proto_key.set_n(key.GetModulus(GetPartialKeyAccess()).GetValue());
  proto_key.set_e(key.GetParameters().GetPublicExponent().GetValue());

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  SecretData serialized_proto = proto_key.SerializeAsSecretData();
  RestrictedData restricted_output = RestrictedData(
      std::move(serialized_proto), InsecureSecretKeyAccess::Get());
  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl, std::move(restricted_output),
      internal::KeyMaterialTypeEnum::kAsymmetricPublic, *output_prefix_type,
      key.GetIdRequirement());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePrivateKey(
    const RsaSsaPkcs1PrivateKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  absl::StatusOr<internal::HashTypeEnum> hash_type =
      ToProtoHashType(key.GetPublicKey().GetParameters().GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  RsaSsaPkcs1PrivateKeyTP proto_private_key;
  proto_private_key.mutable_public_key()->mutable_params()->set_hash_type(
      *hash_type);
  proto_private_key.mutable_public_key()->set_version(0);
  proto_private_key.mutable_public_key()->set_n(
      key.GetPublicKey().GetModulus(GetPartialKeyAccess()).GetValue());
  proto_private_key.mutable_public_key()->set_e(
      key.GetPublicKey().GetParameters().GetPublicExponent().GetValue());
  proto_private_key.set_version(0);
  proto_private_key.set_p(
      key.GetPrimeP(GetPartialKeyAccess()).GetSecret(*token));
  proto_private_key.set_q(
      key.GetPrimeQ(GetPartialKeyAccess()).GetSecret(*token));
  proto_private_key.set_dp(key.GetPrimeExponentP().GetSecret(*token));
  proto_private_key.set_dq(key.GetPrimeExponentQ().GetSecret(*token));
  proto_private_key.set_d(key.GetPrivateExponent().GetSecret(*token));
  proto_private_key.set_crt(key.GetCrtCoefficient().GetSecret(*token));
  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  SecretData serialized_proto = proto_private_key.SerializeAsSecretData();
  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl, RestrictedData(std::move(serialized_proto), *token),
      internal::KeyMaterialTypeEnum::kAsymmetricPrivate, *output_prefix_type,
      key.GetIdRequirement());
}

RsaSsaPkcs1ProtoParametersParserImpl* RsaSsaPkcs1ProtoParametersParser() {
  static auto* parser = new RsaSsaPkcs1ProtoParametersParserImpl(
      kPrivateTypeUrl, ParseParameters);
  return parser;
}

RsaSsaPkcs1ProtoParametersSerializerImpl*
RsaSsaPkcs1ProtoParametersSerializer() {
  static auto* serializer = new RsaSsaPkcs1ProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return serializer;
}

RsaSsaPkcs1ProtoPublicKeyParserImpl* RsaSsaPkcs1ProtoPublicKeyParser() {
  static auto* parser =
      new RsaSsaPkcs1ProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return parser;
}

RsaSsaPkcs1ProtoPublicKeySerializerImpl* RsaSsaPkcs1ProtoPublicKeySerializer() {
  static auto* serializer =
      new RsaSsaPkcs1ProtoPublicKeySerializerImpl(SerializePublicKey);
  return serializer;
}

RsaSsaPkcs1ProtoPrivateKeyParserImpl* RsaSsaPkcs1ProtoPrivateKeyParser() {
  static auto* parser = new RsaSsaPkcs1ProtoPrivateKeyParserImpl(
      kPrivateTypeUrl, ParsePrivateKey);
  return parser;
}

RsaSsaPkcs1ProtoPrivateKeySerializerImpl*
RsaSsaPkcs1ProtoPrivateKeySerializer() {
  static auto* serializer =
      new RsaSsaPkcs1ProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return serializer;
}

}  // namespace

absl::Status RegisterRsaSsaPkcs1ProtoSerialization() {
  absl::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(RsaSsaPkcs1ProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersSerializer(RsaSsaPkcs1ProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(RsaSsaPkcs1ProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeySerializer(RsaSsaPkcs1ProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(RsaSsaPkcs1ProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(RsaSsaPkcs1ProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
