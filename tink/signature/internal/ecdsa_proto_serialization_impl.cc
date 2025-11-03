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

#include <array>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_encoding_util.h"
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
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::EnumOwningField;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageOwningField;
using ::crypto::tink::internal::proto_parsing::OwningBytesField;
using ::crypto::tink::internal::proto_parsing::OwningField;
using ::crypto::tink::internal::proto_parsing::SecretDataOwningField;
using ::crypto::tink::internal::proto_parsing::Uint32OwningField;
using ::crypto::tink::util::SecretDataAsStringView;

bool EcdsaSignatureEncodingValid(uint32_t c) { return 0 <= c && c <= 2; }

// Enum representing the proto enum `google.crypto.tink.EcdsaSignatureEncoding`.
enum class EcdsaSignatureEncodingEnum : uint32_t {
  kUnknownEncoding = 0,
  kIeeeP1363,
  kDer,
};

class EcdsaParamsTP final : public Message<EcdsaParamsTP> {
 public:
  EcdsaParamsTP() = default;

  HashTypeEnum hash_type() const { return hash_type_.value(); }
  void set_hash_type(HashTypeEnum value) { hash_type_.set_value(value); }

  EllipticCurveTypeEnum curve() const { return curve_.value(); }
  void set_curve(EllipticCurveTypeEnum value) { curve_.set_value(value); }

  EcdsaSignatureEncodingEnum encoding() const { return encoding_.value(); }
  void set_encoding(EcdsaSignatureEncodingEnum value) {
    encoding_.set_value(value);
  }

  bool operator==(const EcdsaParamsTP& other) const {
    return hash_type_.value() == other.hash_type_.value() &&
           curve_.value() == other.curve_.value() &&
           encoding_.value() == other.encoding_.value();
  }

  std::array<const OwningField*, 3> GetFields() const {
    return {&hash_type_, &curve_, &encoding_};
  }

 private:
  EnumOwningField<HashTypeEnum> hash_type_{1, &HashTypeEnumIsValid};
  EnumOwningField<EllipticCurveTypeEnum> curve_{2,
                                                &EllipticCurveTypeEnumIsValid};
  EnumOwningField<EcdsaSignatureEncodingEnum> encoding_{
      3, &EcdsaSignatureEncodingValid};
};

class EcdsaPublicKeyTP final : public Message<EcdsaPublicKeyTP> {
 public:
  EcdsaPublicKeyTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const EcdsaParamsTP& params() const { return params_.value(); }
  EcdsaParamsTP* mutable_params() { return params_.mutable_value(); }

  const std::string& x() const { return x_.value(); }
  void set_x(absl::string_view value) { x_.set_value(value); }

  const std::string& y() const { return y_.value(); }
  void set_y(absl::string_view value) { y_.set_value(value); }

  std::array<const OwningField*, 4> GetFields() const {
    return {&version_, &params_, &x_, &y_};
  }

 private:
  Uint32OwningField version_{1};
  MessageOwningField<EcdsaParamsTP> params_{2};
  OwningBytesField<std::string> x_{3};
  OwningBytesField<std::string> y_{4};
};

class EcdsaPrivateKeyTP final : public Message<EcdsaPrivateKeyTP> {
 public:
  EcdsaPrivateKeyTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const EcdsaPublicKeyTP& public_key() const { return public_key_.value(); }
  EcdsaPublicKeyTP* mutable_public_key() { return public_key_.mutable_value(); }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(absl::string_view value) {
    *key_value_.mutable_value() = util::SecretDataFromStringView(value);
  }

  std::array<const OwningField*, 3> GetFields() const {
    return {&version_, &public_key_, &key_value_};
  }

 private:
  Uint32OwningField version_{1};
  MessageOwningField<EcdsaPublicKeyTP> public_key_{2};
  SecretDataOwningField key_value_{3};
};

class EcdsaKeyFormatTP final : public Message<EcdsaKeyFormatTP> {
 public:
  EcdsaKeyFormatTP() = default;

  const EcdsaParamsTP& params() const { return params_.value(); }
  EcdsaParamsTP* mutable_params() { return params_.mutable_value(); }

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  // This is OK because this class doesn't contain secret data.
  using Message::SerializeAsString;

  std::array<const OwningField*, 2> GetFields() const {
    return {&params_, &version_};
  }

 private:
  MessageOwningField<EcdsaParamsTP> params_{2};
  Uint32OwningField version_{3};
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

absl::StatusOr<EcdsaParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kLegacy:
      return EcdsaParameters::Variant::kLegacy;
    case OutputPrefixTypeEnum::kCrunchy:
      return EcdsaParameters::Variant::kCrunchy;
    case OutputPrefixTypeEnum::kRaw:
      return EcdsaParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return EcdsaParameters::Variant::kTink;
    case OutputPrefixTypeEnum::kWithIdRequirement:
      return EcdsaParameters::Variant::kNoPrefixWithPrehashId;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    EcdsaParameters::Variant variant) {
  switch (variant) {
    case EcdsaParameters::Variant::kLegacy:
      return OutputPrefixTypeEnum::kLegacy;
    case EcdsaParameters::Variant::kCrunchy:
      return OutputPrefixTypeEnum::kCrunchy;
    case EcdsaParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case EcdsaParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    case EcdsaParameters::Variant::kNoPrefixWithPrehashId:
      return OutputPrefixTypeEnum::kWithIdRequirement;
    default:
      return absl::InvalidArgumentError(
          "Could not determine EcdsaParameters::Variant");
  }
}

absl::StatusOr<EcdsaParameters::HashType> ToHashType(HashTypeEnum hash_type) {
  switch (hash_type) {
    case HashTypeEnum::kSha256:
      return EcdsaParameters::HashType::kSha256;
    case HashTypeEnum::kSha384:
      return EcdsaParameters::HashType::kSha384;
    case HashTypeEnum::kSha512:
      return EcdsaParameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError("Could not determine HashType");
  }
}

absl::StatusOr<HashTypeEnum> ToProtoHashType(
    EcdsaParameters::HashType hash_type) {
  switch (hash_type) {
    case EcdsaParameters::HashType::kSha256:
      return HashTypeEnum::kSha256;
    case EcdsaParameters::HashType::kSha384:
      return HashTypeEnum::kSha384;
    case EcdsaParameters::HashType::kSha512:
      return HashTypeEnum::kSha512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine EcdsaParameters::HashType");
  }
}

absl::StatusOr<EcdsaParameters::CurveType> ToCurveType(
    EllipticCurveTypeEnum curve_type) {
  switch (curve_type) {
    case EllipticCurveTypeEnum::kNistP256:
      return EcdsaParameters::CurveType::kNistP256;
    case EllipticCurveTypeEnum::kNistP384:
      return EcdsaParameters::CurveType::kNistP384;
    case EllipticCurveTypeEnum::kNistP521:
      return EcdsaParameters::CurveType::kNistP521;
    default:
      return absl::InvalidArgumentError(
          "Could not determine EllipticCurveType");
  }
}

absl::StatusOr<EllipticCurveTypeEnum> ToProtoCurveType(
    EcdsaParameters::CurveType curve_type) {
  switch (curve_type) {
    case EcdsaParameters::CurveType::kNistP256:
      return EllipticCurveTypeEnum::kNistP256;
    case EcdsaParameters::CurveType::kNistP384:
      return EllipticCurveTypeEnum::kNistP384;
    case EcdsaParameters::CurveType::kNistP521:
      return EllipticCurveTypeEnum::kNistP521;
    default:
      return absl::InvalidArgumentError(
          "Could not determine EcdsaParameters::CurveType");
  }
}

absl::StatusOr<EcdsaParameters::SignatureEncoding> ToSignatureEncoding(
    EcdsaSignatureEncodingEnum signature_encoding) {
  switch (signature_encoding) {
    case EcdsaSignatureEncodingEnum::kDer:
      return EcdsaParameters::SignatureEncoding::kDer;
    case EcdsaSignatureEncodingEnum::kIeeeP1363:
      return EcdsaParameters::SignatureEncoding::kIeeeP1363;
    default:
      return absl::InvalidArgumentError(
          "Could not determine EcdsaSignatureEncoding");
  }
}

absl::StatusOr<EcdsaSignatureEncodingEnum> ToProtoSignatureEncoding(
    EcdsaParameters::SignatureEncoding signature_encoding) {
  switch (signature_encoding) {
    case EcdsaParameters::SignatureEncoding::kDer:
      return EcdsaSignatureEncodingEnum::kDer;
    case EcdsaParameters::SignatureEncoding::kIeeeP1363:
      return EcdsaSignatureEncodingEnum::kIeeeP1363;
    default:
      return absl::InvalidArgumentError(
          "Could not determine EcdsaParameters::SignatureEncoding");
  }
}

absl::StatusOr<int> getEncodingLength(EcdsaParameters::CurveType curveType) {
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
      return absl::InvalidArgumentError("Unable to serialize CurveType");
  }
}

absl::StatusOr<EcdsaParameters> ToParameters(
    OutputPrefixTypeEnum output_prefix_type, const EcdsaParamsTP& params) {
  absl::StatusOr<EcdsaParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<EcdsaParameters::HashType> hash_type =
      ToHashType(params.hash_type());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  absl::StatusOr<EcdsaParameters::CurveType> curve_type =
      ToCurveType(params.curve());
  if (!curve_type.ok()) {
    return curve_type.status();
  }

  absl::StatusOr<EcdsaParameters::SignatureEncoding> encoding =
      ToSignatureEncoding(params.encoding());
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

absl::StatusOr<EcdsaParamsTP> FromParameters(
    const EcdsaParameters& parameters) {
  absl::StatusOr<EllipticCurveTypeEnum> curve =
      ToProtoCurveType(parameters.GetCurveType());
  if (!curve.ok()) {
    return curve.status();
  }

  absl::StatusOr<HashTypeEnum> hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  absl::StatusOr<EcdsaSignatureEncodingEnum> encoding =
      ToProtoSignatureEncoding(parameters.GetSignatureEncoding());
  if (!encoding.ok()) {
    return encoding.status();
  }

  EcdsaParamsTP params;
  params.set_curve(*curve);
  params.set_hash_type(*hash_type);
  params.set_encoding(*encoding);

  return params;
}

absl::StatusOr<EcdsaParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const internal::ProtoKeyTemplate& key_template =
      serialization.GetProtoKeyTemplate();
  if (key_template.type_url() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing EcdsaParameters.");
  }

  EcdsaKeyFormatTP proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError("Failed to parse EcdsaKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  return ToParameters(key_template.output_prefix_type(),
                      proto_key_format.params());
}

absl::StatusOr<EcdsaPublicKey> ParsePublicKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing EcdsaPublicKey.");
  }

  EcdsaPublicKeyTP proto_key;
  if (!proto_key.ParseFromString(serialization.SerializedKeyProto().GetSecret(
          InsecureSecretKeyAccess::Get()))) {
    return absl::InvalidArgumentError("Failed to parse EcdsaPublicKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<EcdsaParameters> parameters =
      ToParameters(serialization.GetOutputPrefixTypeEnum(), proto_key.params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  EcPoint public_point(BigInteger(proto_key.x()), BigInteger(proto_key.y()));
  return EcdsaPublicKey::Create(*parameters, public_point,
                                serialization.IdRequirement(),
                                GetPartialKeyAccess());
}

absl::StatusOr<EcdsaPrivateKey> ParsePrivateKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing EcdsaPrivateKey.");
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  EcdsaPrivateKeyTP proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse EcdsaPrivateKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }
  if (proto_key.public_key().version() != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 public keys are accepted.");
  }

  OutputPrefixTypeEnum output_prefix_type =
      serialization.GetOutputPrefixTypeEnum();

  absl::StatusOr<EcdsaParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<EcdsaParameters> parameters =
      ToParameters(output_prefix_type, proto_key.public_key().params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  EcPoint public_point(BigInteger(proto_key.public_key().x()),
                       BigInteger(proto_key.public_key().y()));
  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters, public_point, serialization.IdRequirement(),
      GetPartialKeyAccess());

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(proto_key.key_value(), *token);
  return EcdsaPrivateKey::Create(*public_key, private_key_value,
                                 GetPartialKeyAccess());
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const EcdsaParameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<EcdsaParamsTP> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }

  EcdsaKeyFormatTP proto_key_format;
  *proto_key_format.mutable_params() = *params;
  proto_key_format.set_version(0);

  std::string serialized_proto = proto_key_format.SerializeAsString();
  return ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, serialized_proto);
}

absl::StatusOr<ProtoKeySerialization> SerializePublicKey(
    const EcdsaPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<EcdsaParamsTP> params = FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  absl::StatusOr<int> enc_length =
      getEncodingLength(key.GetParameters().GetCurveType());
  if (!enc_length.ok()) {
    return enc_length.status();
  }

  absl::StatusOr<std::string> x = GetValueOfFixedLength(
      key.GetPublicPoint(GetPartialKeyAccess()).GetX().GetValue(),
      enc_length.value());
  if (!x.ok()) {
    return x.status();
  }

  absl::StatusOr<std::string> y = GetValueOfFixedLength(
      key.GetPublicPoint(GetPartialKeyAccess()).GetY().GetValue(),
      enc_length.value());
  if (!y.ok()) {
    return y.status();
  }

  EcdsaPublicKeyTP proto_key;
  proto_key.set_version(0);
  *proto_key.mutable_params() = *params;
  proto_key.set_x(*x);
  proto_key.set_y(*y);

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  SecretData serialized_proto = proto_key.SerializeAsSecretData();
  auto restricted_output = RestrictedData(std::move(serialized_proto),
                                          InsecureSecretKeyAccess::Get());
  return ProtoKeySerialization::Create(
      kPublicTypeUrl, std::move(restricted_output),
      KeyMaterialTypeEnum::kAsymmetricPublic, *output_prefix_type,
      key.GetIdRequirement());
}

absl::StatusOr<ProtoKeySerialization> SerializePrivateKey(
    const EcdsaPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<RestrictedBigInteger> restricted_input =
      key.GetPrivateKeyValue(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  absl::StatusOr<EcdsaParamsTP> params =
      FromParameters(key.GetPublicKey().GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  absl::StatusOr<int> enc_length =
      getEncodingLength(key.GetPublicKey().GetParameters().GetCurveType());
  if (!enc_length.ok()) {
    return enc_length.status();
  }

  absl::StatusOr<std::string> x =
      GetValueOfFixedLength(key.GetPublicKey()
                                .GetPublicPoint(GetPartialKeyAccess())
                                .GetX()
                                .GetValue(),
                            enc_length.value());
  if (!x.ok()) {
    return x.status();
  }

  absl::StatusOr<std::string> y =
      GetValueOfFixedLength(key.GetPublicKey()
                                .GetPublicPoint(GetPartialKeyAccess())
                                .GetY()
                                .GetValue(),
                            enc_length.value());
  if (!y.ok()) {
    return y.status();
  }

  EcdsaPrivateKeyTP proto_private_key;
  proto_private_key.set_version(0);
  proto_private_key.mutable_public_key()->set_version(0);
  *proto_private_key.mutable_public_key()->mutable_params() = *params;
  proto_private_key.mutable_public_key()->set_x(*x);
  proto_private_key.mutable_public_key()->set_y(*y);
  absl::StatusOr<SecretData> fixed_length_key =
      GetSecretValueOfFixedLength(*restricted_input, *enc_length, *token);
  if (!fixed_length_key.ok()) {
    return fixed_length_key.status();
  }
  proto_private_key.set_key_value(SecretDataAsStringView(*fixed_length_key));

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

absl::Status RegisterEcdsaProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
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

absl::Status RegisterEcdsaProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
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
