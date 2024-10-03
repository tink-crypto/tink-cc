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

#include "tink/experimental/pqcrypto/kem/ml_kem_proto_serialization.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_public_key.h"
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
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/experimental/pqcrypto/ml_kem.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::MlKemKeyFormat;
using ::google::crypto::tink::MlKemKeySize;
using ::google::crypto::tink::MlKemParams;
using ::google::crypto::tink::OutputPrefixType;

using MlKemProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   MlKemParameters>;
using MlKemProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<MlKemParameters,
                                       internal::ProtoParametersSerialization>;
using MlKemProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, MlKemPublicKey>;
using MlKemProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<MlKemPublicKey,
                                internal::ProtoKeySerialization>;
using MlKemProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, MlKemPrivateKey>;
using MlKemProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<MlKemPrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.MlKemPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.MlKemPublicKey";

util::StatusOr<MlKemParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::TINK:
      return MlKemParameters::Variant::kTink;
    case OutputPrefixType::RAW:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid output prefix type RAW for MlKemParameters");
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine MlKemParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    MlKemParameters::Variant variant) {
  switch (variant) {
    case MlKemParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<int> ToKeySize(MlKemKeySize key_size) {
  switch (key_size) {
    case MlKemKeySize::ML_KEM_768:
      return 768;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine MlKemParameters' key size");
  }
}

util::StatusOr<MlKemKeySize> ToProtoKeySize(int key_size) {
  switch (key_size) {
    case 768:
      return MlKemKeySize::ML_KEM_768;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine MlKemKeySize");
  }
}

util::StatusOr<MlKemParameters> ToParameters(
    OutputPrefixType output_prefix_type, const MlKemParams& params) {
  util::StatusOr<MlKemParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<int> key_size = ToKeySize(params.ml_kem_key_size());
  if (!key_size.ok()) {
    return key_size.status();
  }

  return MlKemParameters::Create(*key_size, *variant);
}

util::StatusOr<MlKemParams> FromParameters(const MlKemParameters& parameters) {
  util::StatusOr<MlKemKeySize> key_size =
      ToProtoKeySize(parameters.GetKeySize());
  if (!key_size.ok()) {
    return key_size.status();
  }

  MlKemParams params;
  params.set_ml_kem_key_size(*key_size);
  return params;
}

util::StatusOr<MlKemParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing MlKemParameters.");
  }

  MlKemKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse MlKemKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  if (!proto_key_format.has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "MlKemKeyFormat proto is missing params field.");
  }

  return ToParameters(serialization.GetKeyTemplate().output_prefix_type(),
                      proto_key_format.params());
}

util::StatusOr<MlKemPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing MlKemPublicKey.");
  }

  google::crypto::tink::MlKemPublicKey proto_key;
  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  if (!proto_key.ParseFromString(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse MlKemPublicKey proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<MlKemParameters> parameters =
      ToParameters(serialization.GetOutputPrefixType(), proto_key.params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return MlKemPublicKey::Create(*parameters, proto_key.key_value(),
                                serialization.IdRequirement(),
                                GetPartialKeyAccess());
}

util::StatusOr<MlKemPrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing MlKemPrivateKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  absl::StatusOr<SecretProto<google::crypto::tink::MlKemPrivateKey>> proto_key =
      SecretProto<google::crypto::tink::MlKemPrivateKey>::ParseFromSecretData(
          serialization.SerializedKeyProto().Get(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse MlKemPrivateKey proto");
  }
  if ((*proto_key)->version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<MlKemParameters> parameters = ToParameters(
      serialization.GetOutputPrefixType(), (*proto_key)->public_key().params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  util::StatusOr<MlKemPublicKey> public_key = MlKemPublicKey::Create(
      *parameters, (*proto_key)->public_key().key_value(),
      serialization.IdRequirement(), GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return MlKemPrivateKey::Create(
      *public_key, RestrictedData((*proto_key)->key_value(), *token),
      GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const MlKemParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<MlKemParams> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }
  MlKemKeyFormat proto_key_format;
  *proto_key_format.mutable_params() = *params;
  proto_key_format.set_version(0);

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type,
      proto_key_format.SerializeAsString());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const MlKemPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<MlKemParams> params = FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  google::crypto::tink::MlKemPublicKey proto_key;
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
    const MlKemPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  util::StatusOr<RestrictedData> restricted_input =
      key.GetPrivateSeedBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  util::StatusOr<MlKemParams> params =
      FromParameters(key.GetPublicKey().GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  google::crypto::tink::MlKemPublicKey proto_public_key;
  proto_public_key.set_version(0);
  *proto_public_key.mutable_params() = *params;
  proto_public_key.set_key_value(
      key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess()));

  google::crypto::tink::MlKemPrivateKey proto_private_key;
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

MlKemProtoParametersParserImpl& MlKemProtoParametersParser() {
  static auto parser =
      new MlKemProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return *parser;
}

MlKemProtoParametersSerializerImpl& MlKemProtoParametersSerializer() {
  static auto serializer = new MlKemProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return *serializer;
}

MlKemProtoPublicKeyParserImpl& MlKemProtoPublicKeyParser() {
  static auto* parser =
      new MlKemProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return *parser;
}

MlKemProtoPublicKeySerializerImpl& MlKemProtoPublicKeySerializer() {
  static auto* serializer =
      new MlKemProtoPublicKeySerializerImpl(SerializePublicKey);
  return *serializer;
}

MlKemProtoPrivateKeyParserImpl& MlKemProtoPrivateKeyParser() {
  static auto* parser =
      new MlKemProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return *parser;
}

MlKemProtoPrivateKeySerializerImpl& MlKemProtoPrivateKeySerializer() {
  static auto* serializer =
      new MlKemProtoPrivateKeySerializerImpl(SerializePrivateSeed);
  return *serializer;
}

}  // namespace

util::Status RegisterMlKemProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(&MlKemProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(&MlKemProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&MlKemProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeySerializer(&MlKemProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&MlKemProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(&MlKemProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
