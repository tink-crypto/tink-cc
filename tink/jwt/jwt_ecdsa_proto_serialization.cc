// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/jwt_ecdsa_proto_serialization.h"

#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
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
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_private_key.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;

bool JwtEcdsaAlgorithmValid(int value) {
  return google::crypto::tink::JwtEcdsaAlgorithm_IsValid(value);
}

struct CustomKidStruct {
  std::string value;

  static ProtoParser<CustomKidStruct> CreateParser() {
    return ProtoParserBuilder<CustomKidStruct>()
        .AddBytesStringField(1, &CustomKidStruct::value)
        .BuildOrDie();
  }
};

struct JwtEcdsaPublicKeyStruct {
  uint32_t version;
  JwtEcdsaAlgorithm algorithm;
  std::string x;
  std::string y;
  std::optional<CustomKidStruct> custom_kid;

  static ProtoParser<JwtEcdsaPublicKeyStruct> CreateParser() {
    return ProtoParserBuilder<JwtEcdsaPublicKeyStruct>()
        .AddUint32Field(1, &JwtEcdsaPublicKeyStruct::version)
        .AddEnumField(2, &JwtEcdsaPublicKeyStruct::algorithm,
                      &JwtEcdsaAlgorithmValid)
        .AddBytesStringField(3, &JwtEcdsaPublicKeyStruct::x)
        .AddBytesStringField(4, &JwtEcdsaPublicKeyStruct::y)
        .AddMessageFieldWithPresence(5, &JwtEcdsaPublicKeyStruct::custom_kid,
                                     CustomKidStruct::CreateParser())
        .BuildOrDie();
  }

  static const ProtoParser<JwtEcdsaPublicKeyStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<JwtEcdsaPublicKeyStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

struct JwtEcdsaPrivateKeyStruct {
  uint32_t version;
  JwtEcdsaPublicKeyStruct public_key;
  util::SecretData key_value;

  static const ProtoParser<JwtEcdsaPrivateKeyStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<JwtEcdsaPrivateKeyStruct>> parser{
        ProtoParserBuilder<JwtEcdsaPrivateKeyStruct>()
            .AddUint32Field(1, &JwtEcdsaPrivateKeyStruct::version)
            .AddMessageField(2, &JwtEcdsaPrivateKeyStruct::public_key,
                             JwtEcdsaPublicKeyStruct::CreateParser())
            .AddBytesSecretDataField(3, &JwtEcdsaPrivateKeyStruct::key_value)
            .BuildOrDie()};
    return *parser;
  }
};

struct JwtEcdsaKeyFormatStruct {
  uint32_t version;
  JwtEcdsaAlgorithm algorithm;

  static const ProtoParser<JwtEcdsaKeyFormatStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<JwtEcdsaKeyFormatStruct>> parser{
        ProtoParserBuilder<JwtEcdsaKeyFormatStruct>()
            .AddUint32Field(1, &JwtEcdsaKeyFormatStruct::version)
            .AddEnumField(2, &JwtEcdsaKeyFormatStruct::algorithm,
                          &JwtEcdsaAlgorithmValid)
            .BuildOrDie()};
    return *parser;
  }
};

using JwtEcdsaProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   JwtEcdsaParameters>;
using JwtEcdsaProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<JwtEcdsaParameters,
                                       internal::ProtoParametersSerialization>;
using JwtEcdsaProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, JwtEcdsaPublicKey>;
using JwtEcdsaProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<JwtEcdsaPublicKey,
                                internal::ProtoKeySerialization>;
using JwtEcdsaProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            JwtEcdsaPrivateKey>;
using JwtEcdsaProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<JwtEcdsaPrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey";
const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey";

absl::StatusOr<JwtEcdsaParameters::KidStrategy> ToKidStrategy(
    OutputPrefixType output_prefix_type, bool has_custom_kid) {
  switch (output_prefix_type) {
    case OutputPrefixType::RAW:
      if (has_custom_kid) {
        return JwtEcdsaParameters::KidStrategy::kCustom;
      }
      return JwtEcdsaParameters::KidStrategy::kIgnored;
    case OutputPrefixType::TINK:
      return JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid OutputPrefixType for JwtEcdsaKeyFormat.");
  }
}

absl::StatusOr<OutputPrefixType> ToOutputPrefixType(
    JwtEcdsaParameters::KidStrategy kid_strategy) {
  switch (kid_strategy) {
    case JwtEcdsaParameters::KidStrategy::kCustom:
      return OutputPrefixType::RAW;
    case JwtEcdsaParameters::KidStrategy::kIgnored:
      return OutputPrefixType::RAW;
    case JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId:
      return OutputPrefixType::TINK;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine JwtEcdsaParameters::KidStrategy.");
  }
}

absl::StatusOr<JwtEcdsaParameters::Algorithm> FromProtoAlgorithm(
    JwtEcdsaAlgorithm algorithm) {
  switch (algorithm) {
    case JwtEcdsaAlgorithm::ES256:
      return JwtEcdsaParameters::Algorithm::kEs256;
    case JwtEcdsaAlgorithm::ES384:
      return JwtEcdsaParameters::Algorithm::kEs384;
    case JwtEcdsaAlgorithm::ES512:
      return JwtEcdsaParameters::Algorithm::kEs512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine JwtEcdsaAlgorithm.");
  }
}

absl::StatusOr<JwtEcdsaAlgorithm> ToProtoAlgorithm(
    JwtEcdsaParameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtEcdsaParameters::Algorithm::kEs256:
      return JwtEcdsaAlgorithm::ES256;
    case JwtEcdsaParameters::Algorithm::kEs384:
      return JwtEcdsaAlgorithm::ES384;
    case JwtEcdsaParameters::Algorithm::kEs512:
      return JwtEcdsaAlgorithm::ES512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine JwtEcdsaParameters::Algorithm");
  }
}

absl::StatusOr<JwtEcdsaParameters> ToParameters(
    OutputPrefixType output_prefix_type, JwtEcdsaAlgorithm proto_algorithm,
    bool has_custom_kid) {
  absl::StatusOr<JwtEcdsaParameters::KidStrategy> kid_strategy =
      ToKidStrategy(output_prefix_type, has_custom_kid);
  if (!kid_strategy.ok()) {
    return kid_strategy.status();
  }
  absl::StatusOr<JwtEcdsaParameters::Algorithm> algorithm =
      FromProtoAlgorithm(proto_algorithm);
  if (!algorithm.ok()) {
    return algorithm.status();
  }
  return JwtEcdsaParameters::Create(*kid_strategy, *algorithm);
}

absl::StatusOr<int> GetEncodingLength(JwtEcdsaParameters::Algorithm algorithm) {
  // We currently encode with one extra 0-byte at the beginning, to make sure
  // that parsing is correct. See also b/264525021.
  switch (algorithm) {
    case JwtEcdsaParameters::Algorithm::kEs256:
      return 33;
    case JwtEcdsaParameters::Algorithm::kEs384:
      return 49;
    case JwtEcdsaParameters::Algorithm::kEs512:
      return 67;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Unable to determine JwtEcdsaParameters::Algorithm.");
  }
}

absl::StatusOr<JwtEcdsaPublicKey> ToPublicKey(
    const JwtEcdsaParameters& parameters,
    const JwtEcdsaPublicKeyStruct& public_key_struct,
    absl::optional<int> id_requirement) {
  EcPoint public_point =
      EcPoint(BigInteger(public_key_struct.x), BigInteger(public_key_struct.y));
  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(parameters)
                                           .SetPublicPoint(public_point);
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(*id_requirement);
  }
  if (public_key_struct.custom_kid.has_value()) {
    builder.SetCustomKid(public_key_struct.custom_kid.value().value);
  }
  return builder.Build(GetPartialKeyAccess());
}

absl::StatusOr<JwtEcdsaPublicKeyStruct> ToProtoPublicKey(
    const JwtEcdsaPublicKey& public_key) {
  absl::StatusOr<JwtEcdsaAlgorithm> proto_algorithm =
      ToProtoAlgorithm(public_key.GetParameters().GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  absl::StatusOr<int> enc_length =
      GetEncodingLength(public_key.GetParameters().GetAlgorithm());
  if (!enc_length.ok()) {
    return enc_length.status();
  }

  absl::StatusOr<std::string> x = internal::GetValueOfFixedLength(
      public_key.GetPublicPoint(GetPartialKeyAccess()).GetX().GetValue(),
      *enc_length);
  if (!x.ok()) {
    return x.status();
  }

  absl::StatusOr<std::string> y = internal::GetValueOfFixedLength(
      public_key.GetPublicPoint(GetPartialKeyAccess()).GetY().GetValue(),
      *enc_length);
  if (!y.ok()) {
    return y.status();
  }

  JwtEcdsaPublicKeyStruct public_key_struct;
  public_key_struct.version = 0;
  public_key_struct.algorithm = *proto_algorithm;
  public_key_struct.x = *x;
  public_key_struct.y = *y;
  if (public_key.GetParameters().GetKidStrategy() ==
      JwtEcdsaParameters::KidStrategy::kCustom) {
    public_key_struct.custom_kid = CustomKidStruct{*public_key.GetKid()};
  }

  return public_key_struct;
}

absl::StatusOr<JwtEcdsaParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing JwtEcdsaParameters.");
  }

  absl::StatusOr<JwtEcdsaKeyFormatStruct> key_format_struct =
      JwtEcdsaKeyFormatStruct::GetParser().Parse(
          serialization.GetKeyTemplate().value());
  if (!key_format_struct.ok()) {
    return key_format_struct.status();
  }
  if (key_format_struct->version != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing JwtEcdsaParameters failed: only version 0 is accepted.");
  }

  return ToParameters(serialization.GetKeyTemplate().output_prefix_type(),
                      key_format_struct->algorithm, /*has_custom_kid=*/false);
}

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const JwtEcdsaParameters& parameters) {
  if (parameters.GetKidStrategy() == JwtEcdsaParameters::KidStrategy::kCustom) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Unable to serialize JwtEcdsaParameters::KidStrategy::kCustom.");
  }
  absl::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  absl::StatusOr<JwtEcdsaAlgorithm> proto_algorithm =
      ToProtoAlgorithm(parameters.GetAlgorithm());
  if (!proto_algorithm.ok()) {
    return proto_algorithm.status();
  }

  JwtEcdsaKeyFormatStruct format;
  format.version = 0;
  format.algorithm = *proto_algorithm;

  absl::StatusOr<std::string> serialized_format =
      JwtEcdsaKeyFormatStruct::GetParser().SerializeIntoString(format);
  if (!serialized_format.ok()) {
    return serialized_format.status();
  }
  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, *serialized_format);
}

absl::StatusOr<JwtEcdsaPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing JwtEcdsaPublicKey.");
  }

  absl::StatusOr<JwtEcdsaPublicKeyStruct> public_key_struct =
      JwtEcdsaPublicKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(
              InsecureSecretKeyAccess::Get()));
  if (!public_key_struct.ok()) {
    return public_key_struct.status();
  }
  if (public_key_struct->version != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing JwtEcdsaPublicKey failed: only version 0 is accepted.");
  }

  absl::StatusOr<JwtEcdsaParameters> parameters = ToParameters(
      serialization.GetOutputPrefixType(), public_key_struct->algorithm,
      public_key_struct->custom_kid.has_value());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return ToPublicKey(*parameters, *public_key_struct,
                     serialization.IdRequirement());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const JwtEcdsaPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<JwtEcdsaPublicKeyStruct> proto_public_key =
      ToProtoPublicKey(key);
  if (!proto_public_key.ok()) {
    proto_public_key.status();
  }

  absl::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<std::string> serialized_proto =
      JwtEcdsaPublicKeyStruct::GetParser().SerializeIntoString(
          *proto_public_key);

  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl,
      RestrictedData(*serialized_proto, InsecureSecretKeyAccess::Get()),
      KeyData::ASYMMETRIC_PUBLIC, *output_prefix_type, key.GetIdRequirement());
}

absl::StatusOr<JwtEcdsaPrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing JwtEcdsaPrivateKey.");
  }

  absl::StatusOr<JwtEcdsaPrivateKeyStruct> private_key_struct =
      JwtEcdsaPrivateKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!private_key_struct.ok()) {
    return private_key_struct.status();
  }
  if (private_key_struct->version != 0) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsing JwtEcdsaPrivateKey failed: only version 0 is accepted.");
  }

  absl::StatusOr<JwtEcdsaParameters> parameters =
      ToParameters(serialization.GetOutputPrefixType(),
                   private_key_struct->public_key.algorithm,
                   private_key_struct->public_key.custom_kid.has_value());
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      ToPublicKey(*parameters, private_key_struct->public_key,
                  serialization.IdRequirement());
  if (!public_key.ok()) {
    return public_key.status();
  }

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(private_key_struct->key_value, *token);
  return JwtEcdsaPrivateKey::Create(*public_key, private_key_value,
                                    GetPartialKeyAccess());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePrivateKey(
    const JwtEcdsaPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  absl::StatusOr<JwtEcdsaPublicKeyStruct> public_key_struct =
      ToProtoPublicKey(key.GetPublicKey());
  if (!public_key_struct.ok()) {
    return public_key_struct.status();
  }

  absl::StatusOr<RestrictedBigInteger> restricted_input =
      key.GetPrivateKeyValue(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  absl::StatusOr<int> enc_length =
      GetEncodingLength(key.GetPublicKey().GetParameters().GetAlgorithm());
  if (!enc_length.ok()) {
    return enc_length.status();
  }

  util::SecretProto<JwtEcdsaPrivateKeyStruct> private_key_struct;
  private_key_struct->version = 0;
  private_key_struct->public_key = *std::move(public_key_struct);
  private_key_struct->key_value = *internal::GetSecretValueOfFixedLength(
      *restricted_input, *enc_length, *token);

  absl::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetKidStrategy());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<util::SecretData> serialized_proto_private_key =
      JwtEcdsaPrivateKeyStruct::GetParser().SerializeIntoSecretData(
          *private_key_struct);
  if (!serialized_proto_private_key.ok()) {
    return serialized_proto_private_key.status();
  }
  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl,
      RestrictedData(*std::move(serialized_proto_private_key),
                     InsecureSecretKeyAccess::Get()),
      KeyData::ASYMMETRIC_PRIVATE, *output_prefix_type, key.GetIdRequirement());
}

JwtEcdsaProtoParametersParserImpl& JwtEcdsaProtoParametersParser() {
  static auto* parser =
      new JwtEcdsaProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return *parser;
}

JwtEcdsaProtoParametersSerializerImpl& JwtEcdsaProtoParametersSerializer() {
  static auto* serializer = new JwtEcdsaProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return *serializer;
}

JwtEcdsaProtoPublicKeyParserImpl& JwtEcdsaProtoPublicKeyParser() {
  static auto* parser =
      new JwtEcdsaProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return *parser;
}

JwtEcdsaProtoPublicKeySerializerImpl& JwtEcdsaProtoPublicKeySerializer() {
  static auto* serializer =
      new JwtEcdsaProtoPublicKeySerializerImpl(SerializePublicKey);
  return *serializer;
}

JwtEcdsaProtoPrivateKeyParserImpl& JwtEcdsaProtoPrivateKeyParser() {
  static auto* parser =
      new JwtEcdsaProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return *parser;
}

JwtEcdsaProtoPrivateKeySerializerImpl& JwtEcdsaProtoPrivateKeySerializer() {
  static auto* serializer =
      new JwtEcdsaProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return *serializer;
}

}  // namespace

util::Status RegisterJwtEcdsaProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(&JwtEcdsaProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersSerializer(&JwtEcdsaProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&JwtEcdsaProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeySerializer(&JwtEcdsaProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&JwtEcdsaProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(&JwtEcdsaProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
