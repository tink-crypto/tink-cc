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

#include <cstdint>
#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
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
#include "tink/internal/proto_parser.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretDataFromStringView;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HashType_IsValid;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;

struct RsaSsaPkcs1ParamsStruct {
  HashType hash_type;
};

struct RsaSsaPkcs1PublicKeyStruct {
  uint32_t version;
  RsaSsaPkcs1ParamsStruct params;
  std::string n;
  std::string e;
};

struct RsaSsaPkcs1PrivateKeyStruct {
  uint32_t version;
  RsaSsaPkcs1PublicKeyStruct public_key;
  SecretData d;
  SecretData p;
  SecretData q;
  SecretData dp;
  SecretData dq;
  SecretData crt;
};

struct RsaSsaPkcs1KeyFormatStruct {
  RsaSsaPkcs1ParamsStruct params;
  uint32_t modulus_size_in_bits;
  std::string public_exponent;
};

ProtoParser<RsaSsaPkcs1ParamsStruct> CreateParamParser() {
  return ProtoParserBuilder<RsaSsaPkcs1ParamsStruct>()
      .AddEnumField(1, &RsaSsaPkcs1ParamsStruct::hash_type, &HashType_IsValid)
      .BuildOrDie();
}

ProtoParser<RsaSsaPkcs1PublicKeyStruct> CreatePublicKeyParser() {
  return ProtoParserBuilder<RsaSsaPkcs1PublicKeyStruct>()
      .AddUint32Field(1, &RsaSsaPkcs1PublicKeyStruct::version)
      .AddMessageField(2, &RsaSsaPkcs1PublicKeyStruct::params,
                       CreateParamParser())
      .AddBytesStringField(3, &RsaSsaPkcs1PublicKeyStruct::n)
      .AddBytesStringField(4, &RsaSsaPkcs1PublicKeyStruct::e)
      .BuildOrDie();
}

const ProtoParser<RsaSsaPkcs1PublicKeyStruct>& GetPublicKeyParser() {
  static ProtoParser<RsaSsaPkcs1PublicKeyStruct>* parser =
      new ProtoParser<RsaSsaPkcs1PublicKeyStruct>(CreatePublicKeyParser());
  return *parser;
}

ProtoParser<RsaSsaPkcs1PrivateKeyStruct> CreatePrivateKeyParser() {
  return ProtoParserBuilder<RsaSsaPkcs1PrivateKeyStruct>()
      .AddUint32Field(1, &RsaSsaPkcs1PrivateKeyStruct::version)
      .AddMessageField(2, &RsaSsaPkcs1PrivateKeyStruct::public_key,
                       CreatePublicKeyParser())
      .AddBytesSecretDataField(3, &RsaSsaPkcs1PrivateKeyStruct::d)
      .AddBytesSecretDataField(4, &RsaSsaPkcs1PrivateKeyStruct::p)
      .AddBytesSecretDataField(5, &RsaSsaPkcs1PrivateKeyStruct::q)
      .AddBytesSecretDataField(6, &RsaSsaPkcs1PrivateKeyStruct::dp)
      .AddBytesSecretDataField(7, &RsaSsaPkcs1PrivateKeyStruct::dq)
      .AddBytesSecretDataField(8, &RsaSsaPkcs1PrivateKeyStruct::crt)
      .BuildOrDie();
}

const ProtoParser<RsaSsaPkcs1PrivateKeyStruct>& GetPrivateKeyParser() {
  static ProtoParser<RsaSsaPkcs1PrivateKeyStruct>* parser =
      new ProtoParser<RsaSsaPkcs1PrivateKeyStruct>(CreatePrivateKeyParser());
  return *parser;
}

ProtoParser<RsaSsaPkcs1KeyFormatStruct> CreateKeyFormatParser() {
  return ProtoParserBuilder<RsaSsaPkcs1KeyFormatStruct>()
      .AddMessageField(1, &RsaSsaPkcs1KeyFormatStruct::params,
                       CreateParamParser())
      .AddUint32Field(2, &RsaSsaPkcs1KeyFormatStruct::modulus_size_in_bits)
      .AddBytesStringField(3, &RsaSsaPkcs1KeyFormatStruct::public_exponent)
      .BuildOrDie();
}

const ProtoParser<RsaSsaPkcs1KeyFormatStruct>& GetKeyFormatParser() {
  static ProtoParser<RsaSsaPkcs1KeyFormatStruct>* parser =
      new ProtoParser<RsaSsaPkcs1KeyFormatStruct>(CreateKeyFormatParser());
  return *parser;
}

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

util::StatusOr<RsaSsaPkcs1Parameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      return RsaSsaPkcs1Parameters::Variant::kLegacy;
    case OutputPrefixType::CRUNCHY:
      return RsaSsaPkcs1Parameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return RsaSsaPkcs1Parameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return RsaSsaPkcs1Parameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine RsaSsaPkcs1Parameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    RsaSsaPkcs1Parameters::Variant variant) {
  switch (variant) {
    case RsaSsaPkcs1Parameters::Variant::kLegacy:
      return OutputPrefixType::LEGACY;
    case RsaSsaPkcs1Parameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case RsaSsaPkcs1Parameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case RsaSsaPkcs1Parameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type.");
  }
}

util::StatusOr<RsaSsaPkcs1Parameters::HashType> ToEnumHashType(
    HashType hash_type) {
  switch (hash_type) {
    case HashType::SHA256:
      return RsaSsaPkcs1Parameters::HashType::kSha256;
    case HashType::SHA384:
      return RsaSsaPkcs1Parameters::HashType::kSha384;
    case HashType::SHA512:
      return RsaSsaPkcs1Parameters::HashType::kSha512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HashType");
  }
}

util::StatusOr<HashType> ToProtoHashType(
    RsaSsaPkcs1Parameters::HashType hash_type) {
  switch (hash_type) {
    case RsaSsaPkcs1Parameters::HashType::kSha256:
      return HashType::SHA256;
    case RsaSsaPkcs1Parameters::HashType::kSha384:
      return HashType::SHA384;
    case RsaSsaPkcs1Parameters::HashType::kSha512:
      return HashType::SHA512;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine RsaSsaPkcs1Parameters::HashType");
  }
}

util::StatusOr<RsaSsaPkcs1Parameters> ToParameters(
    OutputPrefixType output_prefix_type, const RsaSsaPkcs1ParamsStruct& params,
    int modulus_size_in_bits, const BigInteger& public_exponent) {
  util::StatusOr<RsaSsaPkcs1Parameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<RsaSsaPkcs1Parameters::HashType> hash_type =
      ToEnumHashType(params.hash_type);
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

util::StatusOr<RsaSsaPkcs1Parameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing RsaSsaPkcs1Parameters.");
  }

  absl::StatusOr<RsaSsaPkcs1KeyFormatStruct> proto_key_format =
      GetKeyFormatParser().Parse(serialization.GetKeyTemplate().value());
  if (!proto_key_format.ok()) {
    return proto_key_format.status();
  }

  return ToParameters(serialization.GetKeyTemplate().output_prefix_type(),
                      proto_key_format->params,
                      proto_key_format->modulus_size_in_bits,
                      BigInteger(proto_key_format->public_exponent));
}

util::StatusOr<RsaSsaPkcs1PublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing RsaSsaPkcs1PublicKey.");
  }

  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  util::StatusOr<RsaSsaPkcs1PublicKeyStruct> proto_key =
      GetPublicKeyParser().Parse(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!proto_key.ok()) {
    return proto_key.status();
  }
  if (proto_key->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  BigInteger modulus(proto_key->n);
  int modulus_size_in_bits = modulus.SizeInBytes() * 8;
  util::StatusOr<RsaSsaPkcs1Parameters> parameters =
      ToParameters(serialization.GetOutputPrefixType(), proto_key->params,
                   modulus_size_in_bits, BigInteger(proto_key->e));
  if (!parameters.ok()) {
    return parameters.status();
  }

  return RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                      serialization.IdRequirement(),
                                      GetPartialKeyAccess());
}

util::StatusOr<RsaSsaPkcs1PrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing RsaSsaPkcs1PrivateKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  absl::StatusOr<RsaSsaPkcs1PrivateKeyStruct> proto_key =
      GetPrivateKeyParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse RsaSsaPkcs1PrivateKey proto");
  }
  if (proto_key->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }
  if (proto_key->public_key.version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  BigInteger modulus(proto_key->public_key.n);
  int modulus_size_in_bits = modulus.SizeInBytes() * 8;

  util::StatusOr<RsaSsaPkcs1Parameters> parameters = ToParameters(
      serialization.GetOutputPrefixType(), proto_key->public_key.params,
      modulus_size_in_bits, BigInteger(proto_key->public_key.e));
  if (!parameters.ok()) {
    return parameters.status();
  }

  util::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   serialization.IdRequirement(),
                                   GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return RsaSsaPkcs1PrivateKey::Builder()
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

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const RsaSsaPkcs1Parameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<HashType> hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }
  RsaSsaPkcs1KeyFormatStruct proto_key_format;
  proto_key_format.params.hash_type = *hash_type;
  proto_key_format.modulus_size_in_bits = parameters.GetModulusSizeInBits();
  proto_key_format.public_exponent =
      std::string(parameters.GetPublicExponent().GetValue());

  util::StatusOr<std::string> serialized =
      GetKeyFormatParser().SerializeIntoString(proto_key_format);
  if (!serialized.ok()) {
    return serialized.status();
  }
  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, *serialized);
}

util::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const RsaSsaPkcs1PublicKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<HashType> hash_type =
      ToProtoHashType(key.GetParameters().GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  RsaSsaPkcs1PublicKeyStruct proto_key;
  proto_key.params.hash_type = *hash_type;
  proto_key.version = 0;
  proto_key.n = std::string(key.GetModulus(GetPartialKeyAccess()).GetValue());
  proto_key.e = std::string(key.GetParameters().GetPublicExponent().GetValue());

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<std::string> serialized =
      GetPublicKeyParser().SerializeIntoString(proto_key);
  if (!serialized.ok()) {
    return serialized.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*serialized, InsecureSecretKeyAccess::Get());
  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl, restricted_output, KeyData::ASYMMETRIC_PUBLIC,
      *output_prefix_type, key.GetIdRequirement());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePrivateKey(
    const RsaSsaPkcs1PrivateKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  util::StatusOr<HashType> hash_type =
      ToProtoHashType(key.GetPublicKey().GetParameters().GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  RsaSsaPkcs1PrivateKeyStruct proto_private_key;
  proto_private_key.public_key.params.hash_type = *hash_type;
  proto_private_key.public_key.version = 0;
  proto_private_key.public_key.n = std::string(
      key.GetPublicKey().GetModulus(GetPartialKeyAccess()).GetValue());
  proto_private_key.public_key.e = std::string(
      key.GetPublicKey().GetParameters().GetPublicExponent().GetValue());

  proto_private_key.version = 0;
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
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<util::SecretData> serialized =
      GetPrivateKeyParser().SerializeIntoSecretData(proto_private_key);
  if (!serialized.ok()) {
    return serialized.status();
  }

  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl, RestrictedData(*serialized, *token),
      KeyData::ASYMMETRIC_PRIVATE, *output_prefix_type, key.GetIdRequirement());
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

util::Status RegisterRsaSsaPkcs1ProtoSerialization() {
  util::Status status =
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
