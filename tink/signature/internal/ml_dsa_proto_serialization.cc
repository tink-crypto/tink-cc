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

#include "tink/signature/internal/ml_dsa_proto_serialization.h"

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
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/ml_dsa.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;
using ::crypto::tink::util::SecretData;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::MlDsaInstance;
using ::google::crypto::tink::OutputPrefixType;

bool InstaceValid(int c) {
  return google::crypto::tink::MlDsaInstance_IsValid(c);
}

struct MlDsaParamsStruct {
  MlDsaInstance ml_dsa_instance;

  static ProtoParser<MlDsaParamsStruct> CreateParser() {
    return ProtoParserBuilder<MlDsaParamsStruct>()
        .AddEnumField(1, &MlDsaParamsStruct::ml_dsa_instance, &InstaceValid)
        .BuildOrDie();
  }

  static const ProtoParser<MlDsaParamsStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<MlDsaParamsStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

struct MlDsaKeyFormatStruct {
  uint32_t version;
  MlDsaParamsStruct params;

  static ProtoParser<MlDsaKeyFormatStruct> CreateParser() {
    return ProtoParserBuilder<MlDsaKeyFormatStruct>()
        .AddUint32Field(1, &MlDsaKeyFormatStruct::version)
        .AddMessageField(2, &MlDsaKeyFormatStruct::params,
                         MlDsaParamsStruct::CreateParser())
        .BuildOrDie();
  }

  static const ProtoParser<MlDsaKeyFormatStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<MlDsaKeyFormatStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

struct MlDsaPublicKeyStruct {
  uint32_t version;
  std::string key_value;
  MlDsaParamsStruct params;

  static ProtoParser<MlDsaPublicKeyStruct> CreateParser() {
    return ProtoParserBuilder<MlDsaPublicKeyStruct>()
        .AddUint32Field(1, &MlDsaPublicKeyStruct::version)
        .AddBytesStringField(2, &MlDsaPublicKeyStruct::key_value)
        .AddMessageField(3, &MlDsaPublicKeyStruct::params,
                         MlDsaParamsStruct::CreateParser())
        .BuildOrDie();
  }

  static const ProtoParser<MlDsaPublicKeyStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<MlDsaPublicKeyStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

struct MlDsaPrivateKeyStruct {
  uint32_t version;
  util::SecretData key_value;
  MlDsaPublicKeyStruct public_key;

  static ProtoParser<MlDsaPrivateKeyStruct> CreateParser() {
    return ProtoParserBuilder<MlDsaPrivateKeyStruct>()
        .AddUint32Field(1, &MlDsaPrivateKeyStruct::version)
        .AddBytesSecretDataField(2, &MlDsaPrivateKeyStruct::key_value)
        .AddMessageField(3, &MlDsaPrivateKeyStruct::public_key,
                         MlDsaPublicKeyStruct::CreateParser())
        .BuildOrDie();
  }

  static const ProtoParser<MlDsaPrivateKeyStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<MlDsaPrivateKeyStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

using MlDsaProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   MlDsaParameters>;
using MlDsaProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<MlDsaParameters,
                                       internal::ProtoParametersSerialization>;
using MlDsaProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, MlDsaPublicKey>;
using MlDsaProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<MlDsaPublicKey,
                                internal::ProtoKeySerialization>;
using MlDsaProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, MlDsaPrivateKey>;
using MlDsaProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<MlDsaPrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.MlDsaPublicKey";

util::StatusOr<MlDsaParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::RAW:
      return MlDsaParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return MlDsaParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine MlDsaParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    MlDsaParameters::Variant variant) {
  switch (variant) {
    case MlDsaParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case MlDsaParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<MlDsaParameters::Instance> ToInstance(
    MlDsaInstance proto_instance) {
  switch (proto_instance) {
    case MlDsaInstance::ML_DSA_65:
      return MlDsaParameters::Instance::kMlDsa65;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine MlDsaParameters::Instance");
  }
}

util::StatusOr<MlDsaInstance> ToProtoInstance(
    MlDsaParameters::Instance instance) {
  switch (instance) {
    case MlDsaParameters::Instance::kMlDsa65:
      return MlDsaInstance::ML_DSA_65;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine MlDsaInstance");
  }
}

util::StatusOr<MlDsaParameters> ToParameters(
    OutputPrefixType output_prefix_type, const MlDsaParamsStruct& params) {
  util::StatusOr<MlDsaParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<MlDsaParameters::Instance> instance =
      ToInstance(params.ml_dsa_instance);
  if (!instance.ok()) {
    return instance.status();
  }

  return MlDsaParameters::Create(*instance, *variant);
}

util::StatusOr<MlDsaParamsStruct> FromParameters(
    const MlDsaParameters& parameters) {
  /* Only ML-DSA-65  is currently supported*/
  util::StatusOr<MlDsaInstance> instance =
      ToProtoInstance(parameters.GetInstance());
  if (!instance.ok()) {
    return instance.status();
  }

  MlDsaParamsStruct params;
  params.ml_dsa_instance = *instance;

  return params;
}

util::StatusOr<MlDsaParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing MlDsaParameters.");
  }

  util::StatusOr<MlDsaKeyFormatStruct> proto_key_format =
      MlDsaKeyFormatStruct::GetParser().Parse(
          serialization.GetKeyTemplate().value());
  if (!proto_key_format.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse MlDsaKeyFormat proto");
  }
  if (proto_key_format->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  return ToParameters(serialization.GetKeyTemplate().output_prefix_type(),
                      proto_key_format->params);
}

util::StatusOr<MlDsaPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing MlDsaPublicKey.");
  }

  util::StatusOr<MlDsaPublicKeyStruct> proto_key =
      MlDsaPublicKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(
              InsecureSecretKeyAccess::Get()));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse MlDsaPublicKey proto");
  }
  if (proto_key->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<MlDsaParameters> parameters =
      ToParameters(serialization.GetOutputPrefixType(), proto_key->params);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return MlDsaPublicKey::Create(*parameters, proto_key->key_value,
                                serialization.IdRequirement(),
                                GetPartialKeyAccess());
}

util::StatusOr<MlDsaPrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing MlDsaPrivateKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  util::StatusOr<MlDsaPrivateKeyStruct> proto_key =
      MlDsaPrivateKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse MlDsaPrivateKey proto");
  }
  if (proto_key->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<MlDsaParameters> parameters = ToParameters(
      serialization.GetOutputPrefixType(), proto_key->public_key.params);
  if (!parameters.ok()) {
    return parameters.status();
  }

  util::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
      *parameters, proto_key->public_key.key_value,
      serialization.IdRequirement(), GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return MlDsaPrivateKey::Create(*public_key,
                                 RestrictedData(proto_key->key_value, *token),
                                 GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const MlDsaParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<MlDsaParamsStruct> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }
  MlDsaKeyFormatStruct proto_key_format;
  proto_key_format.params = *params;
  proto_key_format.version = 0;

  util::StatusOr<std::string> serialized_proto =
      MlDsaKeyFormatStruct::GetParser().SerializeIntoString(proto_key_format);
  if (!serialized_proto.ok()) {
    return serialized_proto.status();
  }

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, *serialized_proto);
}

util::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const MlDsaPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<MlDsaParamsStruct> params =
      FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  MlDsaPublicKeyStruct proto_key;
  proto_key.version = 0;
  proto_key.params = *params;
  proto_key.key_value = key.GetPublicKeyBytes(GetPartialKeyAccess());

  util::StatusOr<std::string> serialized_proto =
      MlDsaPublicKeyStruct::GetParser().SerializeIntoString(proto_key);
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

util::StatusOr<internal::ProtoKeySerialization> SerializePrivateSeed(
    const MlDsaPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  util::StatusOr<RestrictedData> restricted_input =
      key.GetPrivateSeedBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  util::StatusOr<MlDsaParamsStruct> params =
      FromParameters(key.GetPublicKey().GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  MlDsaPrivateKeyStruct proto_private_key;
  proto_private_key.version = 0;
  proto_private_key.public_key.version = 0;
  proto_private_key.public_key.params = *params;
  proto_private_key.public_key.key_value =
      key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());
  proto_private_key.key_value = restricted_input->Get(*token);

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<SecretData> serialized_proto =
      MlDsaPrivateKeyStruct::GetParser().SerializeIntoSecretData(
          proto_private_key);
  if (!serialized_proto.ok()) {
    return serialized_proto.status();
  }
  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl, RestrictedData(*serialized_proto, *token),
      KeyData::ASYMMETRIC_PRIVATE, *output_prefix_type, key.GetIdRequirement());
}

MlDsaProtoParametersParserImpl& MlDsaProtoParametersParser() {
  static auto parser =
      new MlDsaProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return *parser;
}

MlDsaProtoParametersSerializerImpl& MlDsaProtoParametersSerializer() {
  static auto serializer = new MlDsaProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return *serializer;
}

MlDsaProtoPublicKeyParserImpl& MlDsaProtoPublicKeyParser() {
  static auto* parser =
      new MlDsaProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return *parser;
}

MlDsaProtoPublicKeySerializerImpl& MlDsaProtoPublicKeySerializer() {
  static auto* serializer =
      new MlDsaProtoPublicKeySerializerImpl(SerializePublicKey);
  return *serializer;
}

MlDsaProtoPrivateKeyParserImpl& MlDsaProtoPrivateKeyParser() {
  static auto* parser =
      new MlDsaProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return *parser;
}

MlDsaProtoPrivateKeySerializerImpl& MlDsaProtoPrivateKeySerializer() {
  static auto* serializer =
      new MlDsaProtoPrivateKeySerializerImpl(SerializePrivateSeed);
  return *serializer;
}

}  // namespace

util::Status RegisterMlDsaProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(&MlDsaProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(&MlDsaProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&MlDsaProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeySerializer(&MlDsaProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&MlDsaProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(&MlDsaProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
