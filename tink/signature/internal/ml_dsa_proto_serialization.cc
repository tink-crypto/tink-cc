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

#include "absl/status/status.h"
#include "absl/status/statusor.h"
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
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/ml_dsa.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::MlDsaInstance;
using ::google::crypto::tink::MlDsaKeyFormat;
using ::google::crypto::tink::MlDsaParams;
using ::google::crypto::tink::OutputPrefixType;

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
      return util::Status(absl::StatusCode::kInvalidArgument,
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
    OutputPrefixType output_prefix_type, const MlDsaParams& params) {
  util::StatusOr<MlDsaParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<MlDsaParameters::Instance> instance =
      ToInstance(params.ml_dsa_instance());
  if (!instance.ok()) {
    return instance.status();
  }

  return MlDsaParameters::Create(*instance, *variant);
}

util::StatusOr<MlDsaParams> FromParameters(const MlDsaParameters& parameters) {
  /* Only ML-DSA-65  is currently supported*/
  util::StatusOr<MlDsaInstance> instance =
      ToProtoInstance(parameters.GetInstance());
  if (!instance.ok()) {
    return instance.status();
  }

  MlDsaParams params;
  params.set_ml_dsa_instance(*instance);

  return params;
}

util::StatusOr<MlDsaParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing MlDsaParameters.");
  }

  MlDsaKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse MlDsaKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  if (!proto_key_format.has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "MlDsaKeyFormat proto is missing params field.");
  }

  return ToParameters(serialization.GetKeyTemplate().output_prefix_type(),
                      proto_key_format.params());
}

util::StatusOr<MlDsaPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing MlDsaPublicKey.");
  }

  google::crypto::tink::MlDsaPublicKey proto_key;
  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  if (!proto_key.ParseFromString(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse MlDsaPublicKey proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<MlDsaParameters> parameters =
      ToParameters(serialization.GetOutputPrefixType(), proto_key.params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return MlDsaPublicKey::Create(*parameters, proto_key.key_value(),
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
  absl::StatusOr<SecretProto<google::crypto::tink::MlDsaPrivateKey>> proto_key =
      SecretProto<google::crypto::tink::MlDsaPrivateKey>::ParseFromSecretData(
          serialization.SerializedKeyProto().Get(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse MlDsaPrivateKey proto");
  }
  if ((*proto_key)->version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<MlDsaParameters> parameters = ToParameters(
      serialization.GetOutputPrefixType(), (*proto_key)->public_key().params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  util::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
      *parameters, (*proto_key)->public_key().key_value(),
      serialization.IdRequirement(), GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return MlDsaPrivateKey::Create(
      *public_key, RestrictedData((*proto_key)->key_value(), *token),
      GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const MlDsaParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<MlDsaParams> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }
  MlDsaKeyFormat proto_key_format;
  *proto_key_format.mutable_params() = *params;
  proto_key_format.set_version(0);

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type,
      proto_key_format.SerializeAsString());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const MlDsaPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<MlDsaParams> params = FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  google::crypto::tink::MlDsaPublicKey proto_key;
  proto_key.set_version(0);
  *proto_key.mutable_params() = *params;
  proto_key.set_key_value(key.GetPublicKeyBytes(GetPartialKeyAccess()));

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output = RestrictedData(
      proto_key.SerializeAsString(), InsecureSecretKeyAccess::Get());
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

  util::StatusOr<MlDsaParams> params =
      FromParameters(key.GetPublicKey().GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  google::crypto::tink::MlDsaPublicKey proto_public_key;
  proto_public_key.set_version(0);
  *proto_public_key.mutable_params() = *params;
  proto_public_key.set_key_value(
      key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess()));

  google::crypto::tink::MlDsaPrivateKey proto_private_key;
  proto_private_key.set_version(0);
  *proto_private_key.mutable_public_key() = proto_public_key;
  proto_private_key.set_key_value(restricted_input->GetSecret(*token));

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output =
      RestrictedData(proto_private_key.SerializeAsString(), *token);
  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl, restricted_output, KeyData::ASYMMETRIC_PRIVATE,
      *output_prefix_type, key.GetIdRequirement());
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
