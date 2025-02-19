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

#include "tink/prf/internal/hkdf_prf_proto_serialization_impl.h"

#include <string>
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
#include "tink/internal/serialization_registry.h"
#include "tink/partial_key_access.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/hkdf_prf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretProto;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HkdfPrfKeyFormat;
using ::google::crypto::tink::HkdfPrfParams;
using ::google::crypto::tink::OutputPrefixType;

using HkdfPrfProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, HkdfPrfParameters>;
using HkdfPrfProtoParametersSerializerImpl =
    ParametersSerializerImpl<HkdfPrfParameters, ProtoParametersSerialization>;
using HkdfPrfProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, HkdfPrfKey>;
using HkdfPrfProtoKeySerializerImpl =
    KeySerializerImpl<HkdfPrfKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.HkdfPrfKey";

util::StatusOr<HkdfPrfParameters::HashType> ToHashType(HashType hash_type) {
  switch (hash_type) {
    case HashType::SHA1:
      return HkdfPrfParameters::HashType::kSha1;
    case HashType::SHA224:
      return HkdfPrfParameters::HashType::kSha224;
    case HashType::SHA256:
      return HkdfPrfParameters::HashType::kSha256;
    case HashType::SHA384:
      return HkdfPrfParameters::HashType::kSha384;
    case HashType::SHA512:
      return HkdfPrfParameters::HashType::kSha512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HashType");
  }
}

util::StatusOr<HashType> ToProtoHashType(
    HkdfPrfParameters::HashType hash_type) {
  switch (hash_type) {
    case HkdfPrfParameters::HashType::kSha1:
      return HashType::SHA1;
    case HkdfPrfParameters::HashType::kSha224:
      return HashType::SHA224;
    case HkdfPrfParameters::HashType::kSha256:
      return HashType::SHA256;
    case HkdfPrfParameters::HashType::kSha384:
      return HashType::SHA384;
    case HkdfPrfParameters::HashType::kSha512:
      return HashType::SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HkdfPrfParameters::HashType");
  }
}

util::StatusOr<HkdfPrfParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing HkdfPrfParameters.");
  }
  if (serialization.GetKeyTemplate().output_prefix_type() !=
      OutputPrefixType::RAW) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Output prefix type must be RAW for HkdfPrfParameters.");
  }

  HkdfPrfKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse HkdfPrfKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<HkdfPrfParameters::HashType> hash_type =
      ToHashType(proto_key_format.params().hash());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  if (!proto_key_format.params().salt().empty()) {
    return HkdfPrfParameters::Create(proto_key_format.key_size(), *hash_type,
                                     proto_key_format.params().salt());
  }

  return HkdfPrfParameters::Create(proto_key_format.key_size(), *hash_type,
                                   absl::nullopt);
}

util::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const HkdfPrfParameters& parameters) {
  util::StatusOr<HashType> proto_hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!proto_hash_type.ok()) {
    return proto_hash_type.status();
  }

  HkdfPrfKeyFormat proto_key_format;
  proto_key_format.set_version(0);
  proto_key_format.set_key_size(parameters.KeySizeInBytes());

  HkdfPrfParams params;
  params.set_hash(*proto_hash_type);
  if (parameters.GetSalt().has_value()) {
    params.set_salt(*parameters.GetSalt());
  }
  *proto_key_format.mutable_params() = params;

  return ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixType::RAW, proto_key_format.SerializeAsString());
}

util::StatusOr<HkdfPrfKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing HkdfPrfKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required.");
  }
  if (serialization.GetOutputPrefixType() != OutputPrefixType::RAW) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Output prefix type must be RAW for HkdfPrfKey.");
  }

  util::StatusOr<SecretProto<google::crypto::tink::HkdfPrfKey>> proto_key =
      SecretProto<google::crypto::tink::HkdfPrfKey>::ParseFromSecretData(
          serialization.SerializedKeyProto().Get(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse HkdfPrfKey proto");
  }
  if ((*proto_key)->version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<HkdfPrfParameters::HashType> hash_type =
      ToHashType((*proto_key)->params().hash());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  absl::optional<std::string> salt = absl::nullopt;
  if (!(*proto_key)->params().salt().empty()) {
    salt = (*proto_key)->params().salt();
  }

  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      (*proto_key)->key_value().length(), *hash_type, salt);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return HkdfPrfKey::Create(*parameters,
                            RestrictedData((*proto_key)->key_value(), *token),
                            GetPartialKeyAccess());
}

util::StatusOr<ProtoKeySerialization> SerializeKey(
    const HkdfPrfKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required.");
  }
  util::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  util::StatusOr<HashType> proto_hash_type =
      ToProtoHashType(key.GetParameters().GetHashType());
  if (!proto_hash_type.ok()) {
    return proto_hash_type.status();
  }

  HkdfPrfParams params;
  params.set_hash(*proto_hash_type);
  if (key.GetParameters().GetSalt().has_value()) {
    params.set_salt(*key.GetParameters().GetSalt());
  }

  SecretProto<google::crypto::tink::HkdfPrfKey> proto_key;
  proto_key->set_version(0);
  *proto_key->mutable_params() = params;
  CallWithCoreDumpProtection(
      [&]() { proto_key->set_key_value(restricted_input->GetSecret(*token)); });

  util::StatusOr<SecretData> serialized_key = proto_key.SerializeAsSecretData();
  if (!serialized_key.ok()) {
    return serialized_key.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*std::move(serialized_key), *token);

  return ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, google::crypto::tink::KeyData::SYMMETRIC,
      OutputPrefixType::RAW, key.GetIdRequirement());
}

HkdfPrfProtoParametersParserImpl& HkdfPrfProtoParametersParser() {
  static auto* parser =
      new HkdfPrfProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return *parser;
}

HkdfPrfProtoParametersSerializerImpl& HkdfPrfProtoParametersSerializer() {
  static auto* serializer =
      new HkdfPrfProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return *serializer;
}

HkdfPrfProtoKeyParserImpl& HkdfPrfProtoKeyParser() {
  static auto* parser = new HkdfPrfProtoKeyParserImpl(kTypeUrl, ParseKey);
  return *parser;
}

HkdfPrfProtoKeySerializerImpl& HkdfPrfProtoKeySerializer() {
  static auto* serializer = new HkdfPrfProtoKeySerializerImpl(SerializeKey);
  return *serializer;
}

}  // namespace

util::Status RegisterHkdfPrfProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(&HkdfPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      &HkdfPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(&HkdfPrfProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(&HkdfPrfProtoKeySerializer());
}

util::Status RegisterHkdfPrfProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  util::Status status =
      builder.RegisterParametersParser(&HkdfPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      builder.RegisterParametersSerializer(&HkdfPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(&HkdfPrfProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(&HkdfPrfProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
