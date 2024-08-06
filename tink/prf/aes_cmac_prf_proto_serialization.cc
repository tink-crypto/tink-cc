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

#include "tink/prf/aes_cmac_prf_proto_serialization.h"

#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/partial_key_access.h"
#include "tink/prf/aes_cmac_prf_key.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_cmac_prf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::AesCmacPrfKeyFormat;
using ::google::crypto::tink::OutputPrefixType;

using AesCmacPrfProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   AesCmacPrfParameters>;
using AesCmacPrfProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<AesCmacPrfParameters,
                                       internal::ProtoParametersSerialization>;
using AesCmacPrfProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, AesCmacPrfKey>;
using AesCmacPrfProtoKeySerializerImpl =
    internal::KeySerializerImpl<AesCmacPrfKey, internal::ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCmacPrfKey";

util::StatusOr<AesCmacPrfParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesCmacPrfParameters.");
  }
  if (serialization.GetKeyTemplate().output_prefix_type() !=
      OutputPrefixType::RAW) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Output prefix type must be RAW for AesCmacPrfParameters.");
  }

  AesCmacPrfKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesCmacPrfKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  return AesCmacPrfParameters::Create(proto_key_format.key_size());
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const AesCmacPrfParameters& parameters) {
  AesCmacPrfKeyFormat proto_key_format;
  proto_key_format.set_version(0);
  proto_key_format.set_key_size(parameters.KeySizeInBytes());

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixType::RAW, proto_key_format.SerializeAsString());
}

util::StatusOr<AesCmacPrfKey> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing AesCmacPrfKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required.");
  }
  if (serialization.GetOutputPrefixType() != OutputPrefixType::RAW) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Output prefix type must be RAW for AesCmacPrfKey.");
  }

  util::StatusOr<SecretProto<google::crypto::tink::AesCmacPrfKey>> proto_key =
      SecretProto<google::crypto::tink::AesCmacPrfKey>::ParseFromSecretData(
          serialization.SerializedKeyProto().Get(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesCmacPrfKey proto");
  }
  if ((*proto_key)->version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  return AesCmacPrfKey::Create(
      RestrictedData((*proto_key)->key_value(), *token), GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const AesCmacPrfKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required.");
  }
  util::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  SecretProto<google::crypto::tink::AesCmacPrfKey> proto_key;
  proto_key->set_version(0);
  internal::CallWithCoreDumpProtection(
      [&]() { proto_key->set_key_value(restricted_input->GetSecret(*token)); });

  util::StatusOr<SecretData> serialized_key = proto_key.SerializeAsSecretData();
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*std::move(serialized_key), *token);

  return internal::ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, google::crypto::tink::KeyData::SYMMETRIC,
      OutputPrefixType::RAW, key.GetIdRequirement());
}

AesCmacPrfProtoParametersParserImpl* AesCmacPrfProtoParametersParser() {
  static auto* parser =
      new AesCmacPrfProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

AesCmacPrfProtoParametersSerializerImpl* AesCmacPrfProtoParametersSerializer() {
  static auto* serializer = new AesCmacPrfProtoParametersSerializerImpl(
      kTypeUrl, SerializeParameters);
  return serializer;
}

AesCmacPrfProtoKeyParserImpl* AesCmacPrfProtoKeyParser() {
  static auto* parser = new AesCmacPrfProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

AesCmacPrfProtoKeySerializerImpl* AesCmacPrfProtoKeySerializer() {
  static auto* serializer = new AesCmacPrfProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

util::Status RegisterAesCmacPrfProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(AesCmacPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersSerializer(AesCmacPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(AesCmacPrfProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(AesCmacPrfProtoKeySerializer());
}

}  // namespace tink
}  // namespace crypto
