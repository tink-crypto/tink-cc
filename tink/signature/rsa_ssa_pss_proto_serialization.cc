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
#include "tink/internal/proto_parser.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretDataFromStringView;

struct RsaSsaPssParamsStruct {
  internal::HashTypeEnum sig_hash;
  internal::HashTypeEnum mgf1_hash;
  uint32_t salt_length;
};

struct RsaSsaPssPublicKeyStruct {
  uint32_t version;
  RsaSsaPssParamsStruct params;
  std::string n;
  std::string e;
};

struct RsaSsaPssPrivateKeyStruct {
  uint32_t version;
  RsaSsaPssPublicKeyStruct public_key;
  SecretData d;
  SecretData p;
  SecretData q;
  SecretData dp;
  SecretData dq;
  SecretData crt;
};

struct RsaSsaPssKeyFormatStruct {
  RsaSsaPssParamsStruct params;
  uint32_t modulus_size_in_bits;
  std::string public_exponent;
};

ProtoParser<RsaSsaPssParamsStruct> CreateParamParser() {
  return ProtoParserBuilder<RsaSsaPssParamsStruct>()
      .AddEnumField(1, &RsaSsaPssParamsStruct::sig_hash,
                    &internal::HashTypeEnumIsValid)
      .AddEnumField(2, &RsaSsaPssParamsStruct::mgf1_hash,
                    &internal::HashTypeEnumIsValid)
      .AddUint32Field(3, &RsaSsaPssParamsStruct::salt_length)
      .BuildOrDie();
}

ProtoParser<RsaSsaPssPublicKeyStruct> CreatePublicKeyParser() {
  return ProtoParserBuilder<RsaSsaPssPublicKeyStruct>()
      .AddUint32Field(1, &RsaSsaPssPublicKeyStruct::version)
      .AddMessageField(2, &RsaSsaPssPublicKeyStruct::params,
                       CreateParamParser())
      .AddBytesStringField(3, &RsaSsaPssPublicKeyStruct::n)
      .AddBytesStringField(4, &RsaSsaPssPublicKeyStruct::e)
      .BuildOrDie();
}

const ProtoParser<RsaSsaPssPublicKeyStruct>& GetPublicKeyParser() {
  static ProtoParser<RsaSsaPssPublicKeyStruct>* parser =
      new ProtoParser<RsaSsaPssPublicKeyStruct>(CreatePublicKeyParser());
  return *parser;
}

ProtoParser<RsaSsaPssPrivateKeyStruct> CreatePrivateKeyParser() {
  return ProtoParserBuilder<RsaSsaPssPrivateKeyStruct>()
      .AddUint32Field(1, &RsaSsaPssPrivateKeyStruct::version)
      .AddMessageField(2, &RsaSsaPssPrivateKeyStruct::public_key,
                       CreatePublicKeyParser())
      .AddBytesSecretDataField(3, &RsaSsaPssPrivateKeyStruct::d)
      .AddBytesSecretDataField(4, &RsaSsaPssPrivateKeyStruct::p)
      .AddBytesSecretDataField(5, &RsaSsaPssPrivateKeyStruct::q)
      .AddBytesSecretDataField(6, &RsaSsaPssPrivateKeyStruct::dp)
      .AddBytesSecretDataField(7, &RsaSsaPssPrivateKeyStruct::dq)
      .AddBytesSecretDataField(8, &RsaSsaPssPrivateKeyStruct::crt)
      .BuildOrDie();
}

const ProtoParser<RsaSsaPssPrivateKeyStruct>& GetPrivateKeyParser() {
  static ProtoParser<RsaSsaPssPrivateKeyStruct>* parser =
      new ProtoParser<RsaSsaPssPrivateKeyStruct>(CreatePrivateKeyParser());
  return *parser;
}

ProtoParser<RsaSsaPssKeyFormatStruct> CreateKeyFormatParser() {
  return ProtoParserBuilder<RsaSsaPssKeyFormatStruct>()
      .AddMessageField(1, &RsaSsaPssKeyFormatStruct::params,
                       CreateParamParser())
      .AddUint32Field(2, &RsaSsaPssKeyFormatStruct::modulus_size_in_bits)
      .AddBytesStringField(3, &RsaSsaPssKeyFormatStruct::public_exponent)
      .BuildOrDie();
}

const ProtoParser<RsaSsaPssKeyFormatStruct>& GetKeyFormatParser() {
  static ProtoParser<RsaSsaPssKeyFormatStruct>* parser =
      new ProtoParser<RsaSsaPssKeyFormatStruct>(CreateKeyFormatParser());
  return *parser;
}

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
    const RsaSsaPssParamsStruct& params, int modulus_size_in_bits,
    const BigInteger& public_exponent) {
  absl::StatusOr<RsaSsaPssParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<RsaSsaPssParameters::HashType> sig_hash_type =
      ToEnumHashType(params.sig_hash);
  if (!sig_hash_type.ok()) {
    return sig_hash_type.status();
  }

  absl::StatusOr<RsaSsaPssParameters::HashType> mgf1_hash_type =
      ToEnumHashType(params.mgf1_hash);
  if (!mgf1_hash_type.ok()) {
    return mgf1_hash_type.status();
  }

  return RsaSsaPssParameters::Builder()
      .SetVariant(*variant)
      .SetSigHashType(*sig_hash_type)
      .SetMgf1HashType(*mgf1_hash_type)
      .SetModulusSizeInBits(modulus_size_in_bits)
      .SetPublicExponent(public_exponent)
      .SetSaltLengthInBytes(params.salt_length)
      .Build();
}

absl::StatusOr<RsaSsaPssParamsStruct> FromParameters(
    RsaSsaPssParameters parameters) {
  absl::StatusOr<internal::HashTypeEnum> sig_hash_type =
      ToProtoHashType(parameters.GetSigHashType());
  if (!sig_hash_type.ok()) {
    return sig_hash_type.status();
  }

  absl::StatusOr<internal::HashTypeEnum> mgf1_hash_type =
      ToProtoHashType(parameters.GetMgf1HashType());
  if (!mgf1_hash_type.ok()) {
    return mgf1_hash_type.status();
  }

  RsaSsaPssParamsStruct params;
  params.sig_hash = *sig_hash_type;
  params.mgf1_hash = *mgf1_hash_type;
  params.salt_length = parameters.GetSaltLengthInBytes();

  return params;
}

absl::StatusOr<RsaSsaPssParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  const internal::KeyTemplateStruct key_template =
      serialization.GetKeyTemplateStruct();
  if (key_template.type_url != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing RsaSsaPssParameters.");
  }

  absl::StatusOr<RsaSsaPssKeyFormatStruct> proto_key_format =
      GetKeyFormatParser().Parse(key_template.value);
  if (!proto_key_format.ok()) {
    return proto_key_format.status();
  }

  return ToParameters(key_template.output_prefix_type, proto_key_format->params,
                      proto_key_format->modulus_size_in_bits,
                      BigInteger(proto_key_format->public_exponent));
}

absl::StatusOr<RsaSsaPssPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing RsaSsaPssPublicKey.");
  }

  absl::StatusOr<RsaSsaPssPublicKeyStruct> proto_key =
      GetPublicKeyParser().Parse(serialization.SerializedKeyProto().GetSecret(
          InsecureSecretKeyAccess::Get()));
  if (!proto_key.ok()) {
    return proto_key.status();
  }
  if (proto_key->version != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  int modulus_size_in_bits = proto_key->n.size() * 8;
  absl::StatusOr<RsaSsaPssParameters> parameters = ToParameters(
      static_cast<internal::OutputPrefixTypeEnum>(
          serialization.GetOutputPrefixType()),
      proto_key->params, modulus_size_in_bits, BigInteger(proto_key->e));
  if (!parameters.ok()) {
    return parameters.status();
  }

  return RsaSsaPssPublicKey::Create(*parameters, BigInteger(proto_key->n),
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
  absl::StatusOr<RsaSsaPssPrivateKeyStruct> proto_key =
      GetPrivateKeyParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!proto_key.ok()) {
    return absl::InvalidArgumentError(
        "Failed to parse RsaSsaPssPrivateKey proto");
  }
  if (proto_key->version != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  if (proto_key->public_key.version != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 public keys are accepted.");
  }

  int modulus_size_in_bits = proto_key->public_key.n.size() * 8;

  absl::StatusOr<RsaSsaPssParameters> parameters =
      ToParameters(static_cast<internal::OutputPrefixTypeEnum>(
                       serialization.GetOutputPrefixType()),
                   proto_key->public_key.params, modulus_size_in_bits,
                   BigInteger(proto_key->public_key.e));
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, BigInteger(proto_key->public_key.n),
      serialization.IdRequirement(), GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return RsaSsaPssPrivateKey::Builder()
      .SetPublicKey(*public_key)
      .SetPrimeP(
          RestrictedBigInteger(SecretDataAsStringView(proto_key->p), *token))
      .SetPrimeQ(
          RestrictedBigInteger(SecretDataAsStringView(proto_key->q), *token))
      .SetPrimeExponentP(
          RestrictedBigInteger(SecretDataAsStringView(proto_key->dp), *token))
      .SetPrimeExponentQ(
          RestrictedBigInteger(SecretDataAsStringView(proto_key->dq), *token))
      .SetPrivateExponent(
          RestrictedBigInteger(SecretDataAsStringView(proto_key->d), *token))
      .SetCrtCoefficient(
          RestrictedBigInteger(SecretDataAsStringView(proto_key->crt), *token))
      .Build(GetPartialKeyAccess());
}

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const RsaSsaPssParameters& parameters) {
  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<RsaSsaPssParamsStruct> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }

  RsaSsaPssKeyFormatStruct proto_key_format;
  proto_key_format.modulus_size_in_bits = parameters.GetModulusSizeInBits();
  proto_key_format.public_exponent =
      std::string(parameters.GetPublicExponent().GetValue());
  proto_key_format.params = *params;

  absl::StatusOr<std::string> serialized =
      GetKeyFormatParser().SerializeIntoString(proto_key_format);
  if (!serialized.ok()) {
    return serialized.status();
  }
  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, *serialized);
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const RsaSsaPssPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<RsaSsaPssParamsStruct> params =
      FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  RsaSsaPssPublicKeyStruct proto_key;
  proto_key.version = 0;
  proto_key.params = *params;
  proto_key.n = std::string(key.GetModulus(GetPartialKeyAccess()).GetValue());
  proto_key.e = std::string(key.GetParameters().GetPublicExponent().GetValue());

  absl::StatusOr<std::string> serialized =
      GetPublicKeyParser().SerializeIntoString(proto_key);
  if (!serialized.ok()) {
    return serialized.status();
  }
  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*serialized, InsecureSecretKeyAccess::Get());
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

  absl::StatusOr<RsaSsaPssParamsStruct> params =
      FromParameters(key.GetPublicKey().GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  RsaSsaPssPublicKeyStruct proto_public_key;
  proto_public_key.version = 0;
  proto_public_key.params = *params;
  proto_public_key.n = std::string(
      key.GetPublicKey().GetModulus(GetPartialKeyAccess()).GetValue());
  proto_public_key.e = std::string(
      key.GetPublicKey().GetParameters().GetPublicExponent().GetValue());

  RsaSsaPssPrivateKeyStruct proto_private_key;
  proto_private_key.version = 0;
  proto_private_key.public_key = std::move(proto_public_key);
  // OSS proto library complains if input is not converted to a string.
  proto_private_key.p = SecretDataFromStringView(
      key.GetPrimeP(GetPartialKeyAccess()).GetSecret(*token));
  proto_private_key.q = SecretDataFromStringView(
      key.GetPrimeQ(GetPartialKeyAccess()).GetSecret(*token));
  proto_private_key.dp =
      SecretDataFromStringView(key.GetPrimeExponentP().GetSecret(*token));
  proto_private_key.dq =
      SecretDataFromStringView(key.GetPrimeExponentQ().GetSecret(*token));
  proto_private_key.d =
      SecretDataFromStringView(key.GetPrivateExponent().GetSecret(*token));
  proto_private_key.crt =
      SecretDataFromStringView(key.GetCrtCoefficient().GetSecret(*token));

  absl::StatusOr<SecretData> serialized =
      GetPrivateKeyParser().SerializeIntoSecretData(proto_private_key);
  if (!serialized.ok()) {
    return serialized.status();
  }
  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output = RestrictedData(*serialized, *token);
  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl, restricted_output,
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
