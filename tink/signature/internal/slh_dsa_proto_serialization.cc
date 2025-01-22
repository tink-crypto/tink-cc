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

#include "tink/signature/internal/slh_dsa_proto_serialization.h"

#include <cstdint>
#include <string>

#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/proto_parser.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/signature/slh_dsa_private_key.h"
#include "tink/signature/slh_dsa_public_key.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/slh_dsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;
using ::crypto::tink::util::SecretData;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::SlhDsaHashType;
using ::google::crypto::tink::SlhDsaSignatureType;

bool HashTypeValid(int c) {
  return google::crypto::tink::SlhDsaHashType_IsValid(c);
}

bool SignatureTypeValid(int c) {
  return google::crypto::tink::SlhDsaSignatureType_IsValid(c);
}

struct SlhDsaParamsStruct {
  // Note that key_size is defined as int32 in slh_dsa.proto.
  uint32_t key_size;
  SlhDsaHashType hash_type;
  SlhDsaSignatureType sig_type;

  static ProtoParser<SlhDsaParamsStruct> CreateParser() {
    return ProtoParserBuilder<SlhDsaParamsStruct>()
        .AddUint32Field(1, &SlhDsaParamsStruct::key_size)
        .AddEnumField(2, &SlhDsaParamsStruct::hash_type, &HashTypeValid)
        .AddEnumField(3, &SlhDsaParamsStruct::sig_type, &SignatureTypeValid)
        .BuildOrDie();
  }

  static const ProtoParser<SlhDsaParamsStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<SlhDsaParamsStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

struct SlhDsaKeyFormatStruct {
  uint32_t version;
  SlhDsaParamsStruct params;

  static ProtoParser<SlhDsaKeyFormatStruct> CreateParser() {
    return ProtoParserBuilder<SlhDsaKeyFormatStruct>()
        .AddUint32Field(1, &SlhDsaKeyFormatStruct::version)
        .AddMessageField(2, &SlhDsaKeyFormatStruct::params,
                         SlhDsaParamsStruct::CreateParser())
        .BuildOrDie();
  }

  static const ProtoParser<SlhDsaKeyFormatStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<SlhDsaKeyFormatStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

struct SlhDsaPublicKeyStruct {
  uint32_t version;
  std::string key_value;
  SlhDsaParamsStruct params;

  static ProtoParser<SlhDsaPublicKeyStruct> CreateParser() {
    return ProtoParserBuilder<SlhDsaPublicKeyStruct>()
        .AddUint32Field(1, &SlhDsaPublicKeyStruct::version)
        .AddBytesStringField(2, &SlhDsaPublicKeyStruct::key_value)
        .AddMessageField(3, &SlhDsaPublicKeyStruct::params,
                         SlhDsaParamsStruct::CreateParser())
        .BuildOrDie();
  }

  static const ProtoParser<SlhDsaPublicKeyStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<SlhDsaPublicKeyStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

struct SlhDsaPrivateKeyStruct {
  uint32_t version;
  SecretData key_value;
  SlhDsaPublicKeyStruct public_key;

  static ProtoParser<SlhDsaPrivateKeyStruct> CreateParser() {
    return ProtoParserBuilder<SlhDsaPrivateKeyStruct>()
        .AddUint32Field(1, &SlhDsaPrivateKeyStruct::version)
        .AddBytesSecretDataField(2, &SlhDsaPrivateKeyStruct::key_value)
        .AddMessageField(3, &SlhDsaPrivateKeyStruct::public_key,
                         SlhDsaPublicKeyStruct::CreateParser())
        .BuildOrDie();
  }

  static const ProtoParser<SlhDsaPrivateKeyStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<SlhDsaPrivateKeyStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

using SlhDsaProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   SlhDsaParameters>;
using SlhDsaProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<SlhDsaParameters,
                                       internal::ProtoParametersSerialization>;
using SlhDsaProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, SlhDsaPublicKey>;
using SlhDsaProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<SlhDsaPublicKey,
                                internal::ProtoKeySerialization>;
using SlhDsaProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, SlhDsaPrivateKey>;
using SlhDsaProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<SlhDsaPrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.SlhDsaPublicKey";

util::StatusOr<SlhDsaParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::RAW:
      return SlhDsaParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return SlhDsaParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine SlhDsaParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    SlhDsaParameters::Variant variant) {
  switch (variant) {
    case SlhDsaParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case SlhDsaParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<SlhDsaParameters::HashType> ToHashType(
    SlhDsaHashType proto_hash_type) {
  switch (proto_hash_type) {
    case SlhDsaHashType::SHA2:
      return SlhDsaParameters::HashType::kSha2;
    case SlhDsaHashType::SHAKE:
      return SlhDsaParameters::HashType::kShake;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine SlhDsaParameters::HashType");
  }
}

util::StatusOr<SlhDsaHashType> ToProtoHashType(
    SlhDsaParameters::HashType hash_type) {
  switch (hash_type) {
    case SlhDsaParameters::HashType::kSha2:
      return SlhDsaHashType::SHA2;
    case SlhDsaParameters::HashType::kShake:
      return SlhDsaHashType::SHAKE;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine SlhDsaHashType");
  }
}

util::StatusOr<SlhDsaParameters::SignatureType> ToSignatureType(
    SlhDsaSignatureType proto_signature_type) {
  switch (proto_signature_type) {
    case SlhDsaSignatureType::FAST_SIGNING:
      return SlhDsaParameters::SignatureType::kFastSigning;
    case SlhDsaSignatureType::SMALL_SIGNATURE:
      return SlhDsaParameters::SignatureType::kSmallSignature;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine SlhDsaParameters::SignatureType");
  }
}

util::StatusOr<SlhDsaSignatureType> ToProtoSignatureType(
    SlhDsaParameters::SignatureType signature_type) {
  switch (signature_type) {
    case SlhDsaParameters::SignatureType::kFastSigning:
      return SlhDsaSignatureType::FAST_SIGNING;
    case SlhDsaParameters::SignatureType::kSmallSignature:
      return SlhDsaSignatureType::SMALL_SIGNATURE;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine SlhDsaSignatureType");
  }
}

util::StatusOr<SlhDsaParameters> ToParameters(
    OutputPrefixType output_prefix_type, const SlhDsaParamsStruct& params) {
  util::StatusOr<SlhDsaParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<SlhDsaParameters::HashType> hash_type =
      ToHashType(params.hash_type);
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  util::StatusOr<SlhDsaParameters::SignatureType> signature_type =
      ToSignatureType(params.sig_type);
  if (!signature_type.ok()) {
    return signature_type.status();
  }

  return SlhDsaParameters::Create(*hash_type, params.key_size, *signature_type,
                                  *variant);
}

util::StatusOr<SlhDsaParamsStruct> FromParameters(
    const SlhDsaParameters& parameters) {
  /* Only SLH-DSA-SHA2-128s  is currently supported*/
  util::StatusOr<SlhDsaHashType> hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  util::StatusOr<SlhDsaSignatureType> signature_type =
      ToProtoSignatureType(parameters.GetSignatureType());
  if (!signature_type.ok()) {
    return signature_type.status();
  }

  SlhDsaParamsStruct params;
  params.key_size = parameters.GetPrivateKeySizeInBytes();
  params.hash_type = *hash_type;
  params.sig_type = *signature_type;

  return params;
}

util::StatusOr<SlhDsaParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing SlhDsaParameters.");
  }

  util::StatusOr<SlhDsaKeyFormatStruct> proto_key_format =
      SlhDsaKeyFormatStruct::GetParser().Parse(
          serialization.GetKeyTemplate().value());
  if (!proto_key_format.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse SlhDsaKeyFormat proto");
  }
  if (proto_key_format->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  return ToParameters(serialization.GetKeyTemplate().output_prefix_type(),
                      proto_key_format->params);
}

util::StatusOr<SlhDsaPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing SlhDsaPublicKey.");
  }

  util::StatusOr<SlhDsaPublicKeyStruct> proto_key =
      SlhDsaPublicKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(
              InsecureSecretKeyAccess::Get()));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse SlhDsaPublicKey proto");
  }
  if (proto_key->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<SlhDsaParameters> parameters =
      ToParameters(serialization.GetOutputPrefixType(), proto_key->params);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return SlhDsaPublicKey::Create(*parameters, proto_key->key_value,
                                 serialization.IdRequirement(),
                                 GetPartialKeyAccess());
}

util::StatusOr<SlhDsaPrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing SlhDsaPrivateKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  util::StatusOr<SlhDsaPrivateKeyStruct> proto_key =
      SlhDsaPrivateKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse SlhDsaPrivateKey proto");
  }
  if (proto_key->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<SlhDsaParameters> parameters = ToParameters(
      serialization.GetOutputPrefixType(), proto_key->public_key.params);
  if (!parameters.ok()) {
    return parameters.status();
  }

  util::StatusOr<SlhDsaPublicKey> public_key = SlhDsaPublicKey::Create(
      *parameters, proto_key->public_key.key_value,
      serialization.IdRequirement(), GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return SlhDsaPrivateKey::Create(*public_key,
                                  RestrictedData(proto_key->key_value, *token),
                                  GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const SlhDsaParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<SlhDsaParamsStruct> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }
  SlhDsaKeyFormatStruct proto_key_format;
  proto_key_format.params = *params;
  proto_key_format.version = 0;

  util::StatusOr<std::string> serialized_proto =
      SlhDsaKeyFormatStruct::GetParser().SerializeIntoString(proto_key_format);
  if (!serialized_proto.ok()) {
    return serialized_proto.status();
  }

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, *serialized_proto);
}

util::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const SlhDsaPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<SlhDsaParamsStruct> params =
      FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  SlhDsaPublicKeyStruct proto_key;
  proto_key.version = 0;
  proto_key.params = *params;
  proto_key.key_value = key.GetPublicKeyBytes(GetPartialKeyAccess());

  util::StatusOr<std::string> serialized_proto =
      SlhDsaPublicKeyStruct::GetParser().SerializeIntoString(proto_key);
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
  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl, restricted_output, KeyData::ASYMMETRIC_PUBLIC,
      *output_prefix_type, key.GetIdRequirement());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePrivateKey(
    const SlhDsaPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  util::StatusOr<RestrictedData> restricted_input =
      key.GetPrivateKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  util::StatusOr<SlhDsaParamsStruct> params =
      FromParameters(key.GetPublicKey().GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  SlhDsaPrivateKeyStruct proto_private_key;
  proto_private_key.version = 0;
  proto_private_key.public_key.version = 0;
  proto_private_key.public_key.params = *params;
  proto_private_key.public_key.key_value =
      key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());
  proto_private_key.key_value = restricted_input->Get(*token);

  util::StatusOr<SecretData> serialized_proto =
      SlhDsaPrivateKeyStruct::GetParser().SerializeIntoSecretData(
          proto_private_key);
  if (!serialized_proto.ok()) {
    return serialized_proto.status();
  }

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl, RestrictedData(*serialized_proto, *token),
      KeyData::ASYMMETRIC_PRIVATE, *output_prefix_type, key.GetIdRequirement());
}

SlhDsaProtoParametersParserImpl& SlhDsaProtoParametersParser() {
  static auto parser =
      new SlhDsaProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return *parser;
}

SlhDsaProtoParametersSerializerImpl& SlhDsaProtoParametersSerializer() {
  static auto serializer = new SlhDsaProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return *serializer;
}

SlhDsaProtoPublicKeyParserImpl& SlhDsaProtoPublicKeyParser() {
  static auto* parser =
      new SlhDsaProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return *parser;
}

SlhDsaProtoPublicKeySerializerImpl& SlhDsaProtoPublicKeySerializer() {
  static auto* serializer =
      new SlhDsaProtoPublicKeySerializerImpl(SerializePublicKey);
  return *serializer;
}

SlhDsaProtoPrivateKeyParserImpl& SlhDsaProtoPrivateKeyParser() {
  static auto* parser =
      new SlhDsaProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return *parser;
}

SlhDsaProtoPrivateKeySerializerImpl& SlhDsaProtoPrivateKeySerializer() {
  static auto* serializer =
      new SlhDsaProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return *serializer;
}

}  // namespace

util::Status RegisterSlhDsaProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(&SlhDsaProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersSerializer(&SlhDsaProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&SlhDsaProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeySerializer(&SlhDsaProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&SlhDsaProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(&SlhDsaProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
