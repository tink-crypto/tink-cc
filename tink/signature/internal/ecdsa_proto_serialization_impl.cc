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

#include "tink/signature/internal/ecdsa_proto_serialization_impl.h"

#include <cstdint>
#include <string>

#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_encoding_util.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/proto_parser.h"
#include "tink/internal/serialization_registry.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::google::crypto::tink::EcdsaSignatureEncoding;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;

bool HashTypeValid(int c) { return google::crypto::tink::HashType_IsValid(c); }

bool EllipticCurveTypeValid(int c) {
  return google::crypto::tink::EllipticCurveType_IsValid(c);
}

bool EcdsaSignatureEncodingValid(int c) {
  return google::crypto::tink::EcdsaSignatureEncoding_IsValid(c);
}

struct EcdsaParamsStruct {
  HashType hash_type;
  EllipticCurveType curve;
  EcdsaSignatureEncoding encoding;

  static ProtoParser<EcdsaParamsStruct> CreateParser() {
    return ProtoParserBuilder<EcdsaParamsStruct>()
        .AddEnumField(1, &EcdsaParamsStruct::hash_type, &HashTypeValid)
        .AddEnumField(2, &EcdsaParamsStruct::curve, &EllipticCurveTypeValid)
        .AddEnumField(3, &EcdsaParamsStruct::encoding,
                      &EcdsaSignatureEncodingValid)
        .BuildOrDie();
  }

  static const ProtoParser<EcdsaParamsStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<EcdsaParamsStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

struct EcdsaPublicKeyStruct {
  uint32_t version;
  EcdsaParamsStruct params;
  std::string x;
  std::string y;

  static ProtoParser<EcdsaPublicKeyStruct> CreateParser() {
    return ProtoParserBuilder<EcdsaPublicKeyStruct>()
        .AddUint32Field(1, &EcdsaPublicKeyStruct::version)
        .AddMessageField(2, &EcdsaPublicKeyStruct::params,
                         EcdsaParamsStruct::CreateParser())
        .AddBytesStringField(3, &EcdsaPublicKeyStruct::x)
        .AddBytesStringField(4, &EcdsaPublicKeyStruct::y)
        .BuildOrDie();
  }

  static const ProtoParser<EcdsaPublicKeyStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<EcdsaPublicKeyStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

struct EcdsaPrivateKeyStruct {
  uint32_t version;
  EcdsaPublicKeyStruct public_key;
  SecretData key_value;

  static ProtoParser<EcdsaPrivateKeyStruct> CreateParser() {
    return ProtoParserBuilder<EcdsaPrivateKeyStruct>()
        .AddUint32Field(1, &EcdsaPrivateKeyStruct::version)
        .AddMessageField(2, &EcdsaPrivateKeyStruct::public_key,
                         EcdsaPublicKeyStruct::CreateParser())
        .AddBytesSecretDataField(3, &EcdsaPrivateKeyStruct::key_value)
        .BuildOrDie();
  }

  static const ProtoParser<EcdsaPrivateKeyStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<EcdsaPrivateKeyStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

struct EcdsaKeyFormatStruct {
  EcdsaParamsStruct params;
  uint32_t version;

  static ProtoParser<EcdsaKeyFormatStruct> CreateParser() {
    return ProtoParserBuilder<EcdsaKeyFormatStruct>()
        .AddMessageField(2, &EcdsaKeyFormatStruct::params,
                         EcdsaParamsStruct::CreateParser())
        .AddUint32Field(3, &EcdsaKeyFormatStruct::version)
        .BuildOrDie();
  }

  static const ProtoParser<EcdsaKeyFormatStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<EcdsaKeyFormatStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

using EcdsaProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, EcdsaParameters>;
using EcdsaProtoParametersSerializerImpl =
    ParametersSerializerImpl<EcdsaParameters, ProtoParametersSerialization>;
using EcdsaProtoPublicKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, EcdsaPublicKey>;
using EcdsaProtoPublicKeySerializerImpl =
    KeySerializerImpl<EcdsaPublicKey, ProtoKeySerialization>;
using EcdsaProtoPrivateKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, EcdsaPrivateKey>;
using EcdsaProtoPrivateKeySerializerImpl =
    KeySerializerImpl<EcdsaPrivateKey, ProtoKeySerialization>;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

util::StatusOr<EcdsaParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      return EcdsaParameters::Variant::kLegacy;
    case OutputPrefixType::CRUNCHY:
      return EcdsaParameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return EcdsaParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return EcdsaParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    EcdsaParameters::Variant variant) {
  switch (variant) {
    case EcdsaParameters::Variant::kLegacy:
      return OutputPrefixType::LEGACY;
    case EcdsaParameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case EcdsaParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case EcdsaParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine EcdsaParameters::Variant");
  }
}

util::StatusOr<EcdsaParameters::HashType> ToHashType(HashType hash_type) {
  switch (hash_type) {
    case HashType::SHA256:
      return EcdsaParameters::HashType::kSha256;
    case HashType::SHA384:
      return EcdsaParameters::HashType::kSha384;
    case HashType::SHA512:
      return EcdsaParameters::HashType::kSha512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HashType");
  }
}

util::StatusOr<HashType> ToProtoHashType(EcdsaParameters::HashType hash_type) {
  switch (hash_type) {
    case EcdsaParameters::HashType::kSha256:
      return HashType::SHA256;
    case EcdsaParameters::HashType::kSha384:
      return HashType::SHA384;
    case EcdsaParameters::HashType::kSha512:
      return HashType::SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine EcdsaParameters::HashType");
  }
}

util::StatusOr<EcdsaParameters::CurveType> ToCurveType(
    EllipticCurveType curve_type) {
  switch (curve_type) {
    case EllipticCurveType::NIST_P256:
      return EcdsaParameters::CurveType::kNistP256;
    case EllipticCurveType::NIST_P384:
      return EcdsaParameters::CurveType::kNistP384;
    case EllipticCurveType::NIST_P521:
      return EcdsaParameters::CurveType::kNistP521;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine EllipticCurveType");
  }
}

util::StatusOr<EllipticCurveType> ToProtoCurveType(
    EcdsaParameters::CurveType curve_type) {
  switch (curve_type) {
    case EcdsaParameters::CurveType::kNistP256:
      return EllipticCurveType::NIST_P256;
    case EcdsaParameters::CurveType::kNistP384:
      return EllipticCurveType::NIST_P384;
    case EcdsaParameters::CurveType::kNistP521:
      return EllipticCurveType::NIST_P521;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine EcdsaParameters::CurveType");
  }
}

util::StatusOr<EcdsaParameters::SignatureEncoding> ToSignatureEncoding(
    EcdsaSignatureEncoding signature_encoding) {
  switch (signature_encoding) {
    case EcdsaSignatureEncoding::DER:
      return EcdsaParameters::SignatureEncoding::kDer;
    case EcdsaSignatureEncoding::IEEE_P1363:
      return EcdsaParameters::SignatureEncoding::kIeeeP1363;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine EcdsaSignatureEncoding");
  }
}

util::StatusOr<EcdsaSignatureEncoding> ToProtoSignatureEncoding(
    EcdsaParameters::SignatureEncoding signature_encoding) {
  switch (signature_encoding) {
    case EcdsaParameters::SignatureEncoding::kDer:
      return EcdsaSignatureEncoding::DER;
    case EcdsaParameters::SignatureEncoding::kIeeeP1363:
      return EcdsaSignatureEncoding::IEEE_P1363;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine EcdsaParameters::SignatureEncoding");
  }
}

util::StatusOr<int> getEncodingLength(EcdsaParameters::CurveType curveType) {
  // We currently encode with one extra 0 byte at the beginning, to make sure
  // that parsing is correct. See also b/264525021.
  switch (curveType) {
    case EcdsaParameters::CurveType::kNistP256:
      return 33;
    case EcdsaParameters::CurveType::kNistP384:
      return 49;
    case EcdsaParameters::CurveType::kNistP521:
      return 67;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Unable to serialize CurveType");
  }
}

util::StatusOr<EcdsaParameters> ToParameters(
    OutputPrefixType output_prefix_type, const EcdsaParamsStruct& params) {
  util::StatusOr<EcdsaParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<EcdsaParameters::HashType> hash_type =
      ToHashType(params.hash_type);
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  util::StatusOr<EcdsaParameters::CurveType> curve_type =
      ToCurveType(params.curve);
  if (!curve_type.ok()) {
    return curve_type.status();
  }

  util::StatusOr<EcdsaParameters::SignatureEncoding> encoding =
      ToSignatureEncoding(params.encoding);
  if (!encoding.ok()) {
    return encoding.status();
  }

  return EcdsaParameters::Builder()
      .SetVariant(*variant)
      .SetHashType(*hash_type)
      .SetCurveType(*curve_type)
      .SetSignatureEncoding(*encoding)
      .Build();
}

util::StatusOr<EcdsaParamsStruct> FromParameters(
    const EcdsaParameters& parameters) {
  util::StatusOr<EllipticCurveType> curve =
      ToProtoCurveType(parameters.GetCurveType());
  if (!curve.ok()) {
    return curve.status();
  }

  util::StatusOr<HashType> hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  util::StatusOr<EcdsaSignatureEncoding> encoding =
      ToProtoSignatureEncoding(parameters.GetSignatureEncoding());
  if (!encoding.ok()) {
    return encoding.status();
  }

  EcdsaParamsStruct params;
  params.curve = *curve;
  params.hash_type = *hash_type;
  params.encoding = *encoding;

  return params;
}

util::StatusOr<EcdsaParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing EcdsaParameters.");
  }

  util::StatusOr<EcdsaKeyFormatStruct> proto_key_format =
      EcdsaKeyFormatStruct::GetParser().Parse(
          serialization.GetKeyTemplate().value());
  if (!proto_key_format.ok()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse EcdsaKeyFormat proto");
  }
  if (proto_key_format->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  return ToParameters(serialization.GetKeyTemplate().output_prefix_type(),
                      proto_key_format->params);
}

util::StatusOr<EcdsaPublicKey> ParsePublicKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing EcdsaPublicKey.");
  }

  util::StatusOr<EcdsaPublicKeyStruct> proto_key =
      EcdsaPublicKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(
              InsecureSecretKeyAccess::Get()));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse EcdsaPublicKey proto");
  }
  if (proto_key->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<EcdsaParameters> parameters =
      ToParameters(serialization.GetOutputPrefixType(), proto_key->params);
  if (!parameters.ok()) {
    return parameters.status();
  }

  EcPoint public_point(BigInteger(proto_key->x), BigInteger(proto_key->y));
  return EcdsaPublicKey::Create(*parameters, public_point,
                                serialization.IdRequirement(),
                                GetPartialKeyAccess());
}

util::StatusOr<EcdsaPrivateKey> ParsePrivateKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing EcdsaPrivateKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  absl::StatusOr<EcdsaPrivateKeyStruct> proto_key =
      EcdsaPrivateKeyStruct::GetParser().Parse(SecretDataAsStringView(
          serialization.SerializedKeyProto().Get(*token)));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse EcdsaPrivateKey proto");
  }
  if (proto_key->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }
  if (proto_key->public_key.version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 public keys are accepted.");
  }

  util::StatusOr<EcdsaParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<EcdsaParameters> parameters = ToParameters(
      serialization.GetOutputPrefixType(), proto_key->public_key.params);
  if (!parameters.ok()) {
    return parameters.status();
  }

  EcPoint public_point(BigInteger(proto_key->public_key.x),
                       BigInteger(proto_key->public_key.y));
  util::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters, public_point, serialization.IdRequirement(),
      GetPartialKeyAccess());

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(proto_key->key_value, *token);
  return EcdsaPrivateKey::Create(*public_key, private_key_value,
                                 GetPartialKeyAccess());
}

util::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const EcdsaParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<EcdsaParamsStruct> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }

  EcdsaKeyFormatStruct proto_key_format;
  proto_key_format.params = *params;
  proto_key_format.version = 0;

  util::StatusOr<std::string> serialized_proto =
      EcdsaKeyFormatStruct::GetParser().SerializeIntoString(proto_key_format);
  if (!serialized_proto.ok()) {
    return serialized_proto.status();
  }

  return ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, *serialized_proto);
}

util::StatusOr<ProtoKeySerialization> SerializePublicKey(
    const EcdsaPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<EcdsaParamsStruct> params =
      FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  util::StatusOr<int> enc_length =
      getEncodingLength(key.GetParameters().GetCurveType());
  if (!enc_length.ok()) {
    return enc_length.status();
  }

  util::StatusOr<std::string> x = GetValueOfFixedLength(
      key.GetPublicPoint(GetPartialKeyAccess()).GetX().GetValue(),
      enc_length.value());
  if (!x.ok()) {
    return x.status();
  }

  util::StatusOr<std::string> y = GetValueOfFixedLength(
      key.GetPublicPoint(GetPartialKeyAccess()).GetY().GetValue(),
      enc_length.value());
  if (!y.ok()) {
    return y.status();
  }

  EcdsaPublicKeyStruct proto_key;
  proto_key.version = 0;
  proto_key.params = *params;
  proto_key.x = *x;
  proto_key.y = *y;

  util::StatusOr<std::string> serialized_proto =
      EcdsaPublicKeyStruct::GetParser().SerializeIntoString(proto_key);
  if (!serialized_proto.ok()) {
    return serialized_proto.status();
  }

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output =
      RestrictedData(*serialized_proto, InsecureSecretKeyAccess::Get());
  return ProtoKeySerialization::Create(
      kPublicTypeUrl, restricted_output, KeyData::ASYMMETRIC_PUBLIC,
      *output_prefix_type, key.GetIdRequirement());
}

util::StatusOr<ProtoKeySerialization> SerializePrivateKey(
    const EcdsaPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<RestrictedBigInteger> restricted_input =
      key.GetPrivateKeyValue(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  util::StatusOr<EcdsaParamsStruct> params =
      FromParameters(key.GetPublicKey().GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  util::StatusOr<int> enc_length =
      getEncodingLength(key.GetPublicKey().GetParameters().GetCurveType());
  if (!enc_length.ok()) {
    return enc_length.status();
  }

  util::StatusOr<std::string> x =
      GetValueOfFixedLength(key.GetPublicKey()
                                .GetPublicPoint(GetPartialKeyAccess())
                                .GetX()
                                .GetValue(),
                            enc_length.value());
  if (!x.ok()) {
    return x.status();
  }

  util::StatusOr<std::string> y =
      GetValueOfFixedLength(key.GetPublicKey()
                                .GetPublicPoint(GetPartialKeyAccess())
                                .GetY()
                                .GetValue(),
                            enc_length.value());
  if (!y.ok()) {
    return y.status();
  }

  EcdsaPrivateKeyStruct proto_private_key;
  proto_private_key.version = 0;
  proto_private_key.public_key.version = 0;
  proto_private_key.public_key.params = *params;
  proto_private_key.public_key.x = *x;
  proto_private_key.public_key.y = *y;
  util::StatusOr<util::SecretData> fixed_length_key =
      GetSecretValueOfFixedLength(*restricted_input, *enc_length, *token);
  if (!fixed_length_key.ok()) {
    return fixed_length_key.status();
  }
  proto_private_key.key_value = *fixed_length_key;

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<util::SecretData> serialized_proto =
      EcdsaPrivateKeyStruct::GetParser().SerializeIntoSecretData(
          proto_private_key);
  if (!serialized_proto.ok()) {
    return serialized_proto.status();
  }
  return ProtoKeySerialization::Create(
      kPrivateTypeUrl, RestrictedData(*serialized_proto, *token),
      KeyData::ASYMMETRIC_PRIVATE, *output_prefix_type, key.GetIdRequirement());
}

EcdsaProtoParametersParserImpl& EcdsaProtoParametersParser() {
  static auto* parser =
      new EcdsaProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return *parser;
}

EcdsaProtoParametersSerializerImpl& EcdsaProtoParametersSerializer() {
  static auto* serializer = new EcdsaProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return *serializer;
}

EcdsaProtoPublicKeyParserImpl& EcdsaProtoPublicKeyParser() {
  static auto* parser =
      new EcdsaProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return *parser;
}

EcdsaProtoPublicKeySerializerImpl& EcdsaProtoPublicKeySerializer() {
  static auto* serializer =
      new EcdsaProtoPublicKeySerializerImpl(SerializePublicKey);
  return *serializer;
}

EcdsaProtoPrivateKeyParserImpl& EcdsaProtoPrivateKeyParser() {
  static auto* parser =
      new EcdsaProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return *parser;
}

EcdsaProtoPrivateKeySerializerImpl& EcdsaProtoPrivateKeySerializer() {
  static auto* serializer =
      new EcdsaProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return *serializer;
}
}  // namespace

util::Status RegisterEcdsaProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  util::Status status =
      registry.RegisterParametersParser(&EcdsaProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      registry.RegisterParametersSerializer(&EcdsaProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(&EcdsaProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeySerializer(&EcdsaProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(&EcdsaProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(&EcdsaProtoPrivateKeySerializer());
}

util::Status RegisterEcdsaProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  util::Status status =
      builder.RegisterParametersParser(&EcdsaProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      builder.RegisterParametersSerializer(&EcdsaProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(&EcdsaProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeySerializer(&EcdsaProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(&EcdsaProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(&EcdsaProtoPrivateKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
