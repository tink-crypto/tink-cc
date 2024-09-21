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

#include "tink/aead/x_aes_gcm_proto_serialization.h"

#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/aead/x_aes_gcm_parameters.h"
#include "tink/internal/call_with_core_dump_protection.h"
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
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"
#include "proto/x_aes_gcm.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::XAesGcmKeyFormat;

using XAesGcmProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   XAesGcmParameters>;
using XAesGcmProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<XAesGcmParameters,
                                       internal::ProtoParametersSerialization>;
using XAesGcmProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, XAesGcmKey>;
using XAesGcmProtoKeySerializerImpl =
    internal::KeySerializerImpl<XAesGcmKey, internal::ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.XAesGcmKey";

util::StatusOr<XAesGcmParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::RAW:
      return XAesGcmParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return XAesGcmParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine XAesGcmParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    XAesGcmParameters::Variant variant) {
  switch (variant) {
    case XAesGcmParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case XAesGcmParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<XAesGcmParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing XAesGcmParameters.");
  }

  XAesGcmKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse XAesGcmKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<XAesGcmParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) {
    return variant.status();
  }

  return XAesGcmParameters::Create(*variant,
                                   proto_key_format.params().salt_size());
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const XAesGcmParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  XAesGcmKeyFormat proto_key_format;
  proto_key_format.set_version(0);
  proto_key_format.mutable_params()->set_salt_size(parameters.SaltSizeBytes());

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

util::StatusOr<XAesGcmKey> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing XAesGcmKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  util::StatusOr<SecretProto<google::crypto::tink::XAesGcmKey>> proto_key =
      SecretProto<google::crypto::tink::XAesGcmKey>::ParseFromSecretData(
          serialization.SerializedKeyProto().Get(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse XAesGcmKey proto");
  }
  if ((*proto_key)->version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<XAesGcmParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<XAesGcmParameters> parameters =
      XAesGcmParameters::Create(*variant, (*proto_key)->params().salt_size());
  if (!parameters.ok()) {
    return parameters.status();
  }
  return XAesGcmKey::Create(
      *parameters, RestrictedData((*proto_key)->key_value(), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const XAesGcmKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  SecretProto<google::crypto::tink::XAesGcmKey> proto_key;
  proto_key->set_version(0);
  proto_key->mutable_params()->set_salt_size(
      key.GetParameters().SaltSizeBytes());
  internal::CallWithCoreDumpProtection(
      [&]() { proto_key->set_key_value(restricted_input->GetSecret(*token)); });

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  util::StatusOr<SecretData> serialized_key = proto_key.SerializeAsSecretData();
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  return internal::ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(*std::move(serialized_key), *token),
      google::crypto::tink::KeyData::SYMMETRIC, *output_prefix_type,
      key.GetIdRequirement());
}

XAesGcmProtoParametersParserImpl* XAesGcmProtoParametersParser() {
  static auto* parser =
      new XAesGcmProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

XAesGcmProtoParametersSerializerImpl* XAesGcmProtoParametersSerializer() {
  static auto* serializer =
      new XAesGcmProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return serializer;
}

XAesGcmProtoKeyParserImpl* XAesGcmProtoKeyParser() {
  static auto* parser = new XAesGcmProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

XAesGcmProtoKeySerializerImpl* XAesGcmProtoKeySerializer() {
  static auto* serializer = new XAesGcmProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

util::Status RegisterXAesGcmProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(XAesGcmProtoParametersParser());
  if (!status.ok()) {
    return status;
  }
  status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersSerializer(XAesGcmProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }
  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(XAesGcmProtoKeyParser());
  if (!status.ok()) {
    return status;
  }
  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(XAesGcmProtoKeySerializer());
}

}  // namespace tink
}  // namespace crypto
