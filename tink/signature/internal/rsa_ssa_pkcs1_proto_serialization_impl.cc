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

#include "tink/signature/internal/rsa_ssa_pkcs1_proto_serialization_impl.h"

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
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_secret_data_field.h"
#include "tink/internal/serialization_registry.h"
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
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::EnumField;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageField;
using ::crypto::tink::internal::proto_parsing::BytesField;
using ::crypto::tink::internal::proto_parsing::Field;
using ::crypto::tink::internal::proto_parsing::SecretDataField;
using ::crypto::tink::internal::proto_parsing::Uint32Field;
using ::crypto::tink::util::SecretDataAsStringView;

class RsaSsaPkcs1ParamsTP : public Message {
 public:
  RsaSsaPkcs1ParamsTP() = default;

  void set_hash_type(HashTypeEnum hash_type) {
    hash_type_.set_value(hash_type);
  }
  HashTypeEnum hash_type() const { return hash_type_.value(); }

 private:
  size_t num_fields() const override { return 1; }
  const Field* field(int i) const override {
    return std::array<const Field*, 1>{&hash_type_}[i];
  }

  EnumField<HashTypeEnum> hash_type_{1, HashTypeEnumIsValid};
};

class RsaSsaPkcs1PublicKeyMessageTP final : public Message {
 public:
  RsaSsaPkcs1PublicKeyMessageTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const RsaSsaPkcs1ParamsTP& params() const { return params_.value(); }
  RsaSsaPkcs1ParamsTP* mutable_params() { return params_.mutable_value(); }

  const std::string& n() const { return n_.value(); }
  void set_n(absl::string_view n) { n_.set_value(n); }

  const std::string& e() const { return e_.value(); }
  void set_e(absl::string_view e) { e_.set_value(e); }

 private:
  size_t num_fields() const override { return 4; }
  const Field* field(int i) const override {
    return std::array<const Field*, 4>{&version_, &params_, &n_, &e_}[i];
  }

  Uint32Field version_{1};
  MessageField<RsaSsaPkcs1ParamsTP> params_{2};
  BytesField n_{3};
  BytesField e_{4};
};

class RsaSsaPkcs1PrivateKeyTP final : public Message {
 public:
  RsaSsaPkcs1PrivateKeyTP() = default;

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
  size_t num_fields() const override { return 8; }
  const Field* field(int i) const override {
    return std::array<const Field*, 8>{&version_, &public_key_, &d_,  &p_,
                                       &q_,       &dp_,         &dq_, &crt_}[i];
  }

  Uint32Field version_{1};
  MessageField<RsaSsaPkcs1PublicKeyMessageTP> public_key_{2};
  SecretDataField d_{3};
  SecretDataField p_{4};
  SecretDataField q_{5};
  SecretDataField dp_{6};
  SecretDataField dq_{7};
  SecretDataField crt_{8};
};

class RsaSsaPkcs1KeyFormatTP final : public Message {
 public:
  RsaSsaPkcs1KeyFormatTP() = default;

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
  size_t num_fields() const override { return 3; }
  const Field* field(int i) const override {
    return std::array<const Field*, 3>{&params_, &modulus_size_in_bits_,
                                       &public_exponent_}[i];
  }

  MessageField<RsaSsaPkcs1ParamsTP> params_{1};
  Uint32Field modulus_size_in_bits_{2};
  BytesField public_exponent_{3};
};

using RsaSsaPkcs1ProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, RsaSsaPkcs1Parameters>;
using RsaSsaPkcs1ProtoParametersSerializerImpl =
    ParametersSerializerImpl<RsaSsaPkcs1Parameters,
                             ProtoParametersSerialization>;
using RsaSsaPkcs1ProtoPublicKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, RsaSsaPkcs1PublicKey>;
using RsaSsaPkcs1ProtoPublicKeySerializerImpl =
    KeySerializerImpl<RsaSsaPkcs1PublicKey, ProtoKeySerialization>;
using RsaSsaPkcs1ProtoPrivateKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, RsaSsaPkcs1PrivateKey>;
using RsaSsaPkcs1ProtoPrivateKeySerializerImpl =
    KeySerializerImpl<RsaSsaPkcs1PrivateKey, ProtoKeySerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey";

absl::StatusOr<RsaSsaPkcs1Parameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kLegacy:
      return RsaSsaPkcs1Parameters::Variant::kLegacy;
    case OutputPrefixTypeEnum::kCrunchy:
      return RsaSsaPkcs1Parameters::Variant::kCrunchy;
    case OutputPrefixTypeEnum::kRaw:
      return RsaSsaPkcs1Parameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return RsaSsaPkcs1Parameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine RsaSsaPkcs1Parameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    RsaSsaPkcs1Parameters::Variant variant) {
  switch (variant) {
    case RsaSsaPkcs1Parameters::Variant::kLegacy:
      return OutputPrefixTypeEnum::kLegacy;
    case RsaSsaPkcs1Parameters::Variant::kCrunchy:
      return OutputPrefixTypeEnum::kCrunchy;
    case RsaSsaPkcs1Parameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case RsaSsaPkcs1Parameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type.");
  }
}

absl::StatusOr<RsaSsaPkcs1Parameters::HashType> ToEnumHashType(
    HashTypeEnum hash_type) {
  switch (hash_type) {
    case HashTypeEnum::kSha256:
      return RsaSsaPkcs1Parameters::HashType::kSha256;
    case HashTypeEnum::kSha384:
      return RsaSsaPkcs1Parameters::HashType::kSha384;
    case HashTypeEnum::kSha512:
      return RsaSsaPkcs1Parameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError("Could not determine HashType");
  }
}

absl::StatusOr<HashTypeEnum> ToProtoHashType(
    RsaSsaPkcs1Parameters::HashType hash_type) {
  switch (hash_type) {
    case RsaSsaPkcs1Parameters::HashType::kSha256:
      return HashTypeEnum::kSha256;
    case RsaSsaPkcs1Parameters::HashType::kSha384:
      return HashTypeEnum::kSha384;
    case RsaSsaPkcs1Parameters::HashType::kSha512:
      return HashTypeEnum::kSha512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine RsaSsaPkcs1Parameters::HashType");
  }
}

absl::StatusOr<RsaSsaPkcs1Parameters> ToParameters(
    OutputPrefixTypeEnum output_prefix_type, const RsaSsaPkcs1ParamsTP& params,
    int modulus_size_in_bits, const BigInteger& public_exponent) {
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
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateTP key_template = serialization.GetKeyTemplate();
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
    const ProtoKeySerialization& serialization,
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
    const ProtoKeySerialization& serialization,
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

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const RsaSsaPkcs1Parameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<HashTypeEnum> hash_type =
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
  return ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, serialized_proto);
}

absl::StatusOr<ProtoKeySerialization> SerializePublicKey(
    const RsaSsaPkcs1PublicKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<HashTypeEnum> hash_type =
      ToProtoHashType(key.GetParameters().GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  RsaSsaPkcs1PublicKeyMessageTP proto_key;
  proto_key.mutable_params()->set_hash_type(*hash_type);
  proto_key.set_version(0);
  proto_key.set_n(key.GetModulus(GetPartialKeyAccess()).GetValue());
  proto_key.set_e(key.GetParameters().GetPublicExponent().GetValue());

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  SecretData serialized_proto = proto_key.SerializeAsSecretData();
  RestrictedData restricted_output = RestrictedData(
      std::move(serialized_proto), InsecureSecretKeyAccess::Get());
  return ProtoKeySerialization::Create(
      kPublicTypeUrl, std::move(restricted_output),
      KeyMaterialTypeEnum::kAsymmetricPublic, *output_prefix_type,
      key.GetIdRequirement());
}

absl::StatusOr<ProtoKeySerialization> SerializePrivateKey(
    const RsaSsaPkcs1PrivateKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  absl::StatusOr<HashTypeEnum> hash_type =
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
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  SecretData serialized_proto = proto_private_key.SerializeAsSecretData();
  return ProtoKeySerialization::Create(
      kPrivateTypeUrl, RestrictedData(std::move(serialized_proto), *token),
      KeyMaterialTypeEnum::kAsymmetricPrivate, *output_prefix_type,
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

absl::Status RegisterRsaSsaPkcs1ProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  if (absl::Status status = registry.RegisterParametersParser(
          RsaSsaPkcs1ProtoParametersParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = registry.RegisterParametersSerializer(
          RsaSsaPkcs1ProtoParametersSerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          registry.RegisterKeyParser(RsaSsaPkcs1ProtoPublicKeyParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = registry.RegisterKeySerializer(
          RsaSsaPkcs1ProtoPublicKeySerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          registry.RegisterKeyParser(RsaSsaPkcs1ProtoPrivateKeyParser());
      !status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(RsaSsaPkcs1ProtoPrivateKeySerializer());
}

absl::Status RegisterRsaSsaPkcs1ProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  if (absl::Status status =
          builder.RegisterParametersParser(RsaSsaPkcs1ProtoParametersParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status = builder.RegisterParametersSerializer(
          RsaSsaPkcs1ProtoParametersSerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          builder.RegisterKeyParser(RsaSsaPkcs1ProtoPublicKeyParser());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          builder.RegisterKeySerializer(RsaSsaPkcs1ProtoPublicKeySerializer());
      !status.ok()) {
    return status;
  }

  if (absl::Status status =
          builder.RegisterKeyParser(RsaSsaPkcs1ProtoPrivateKeyParser());
      !status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(RsaSsaPkcs1ProtoPrivateKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
