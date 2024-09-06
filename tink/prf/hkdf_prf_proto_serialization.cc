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

#include "tink/prf/hkdf_prf_proto_serialization.h"

#include <new>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/hkdf_prf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::util::SecretData;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HkdfPrfKeyFormat;
using ::google::crypto::tink::HkdfPrfParams;
using ::google::crypto::tink::OutputPrefixType;

using HkdfPrfProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   HkdfPrfParameters>;
using HkdfPrfProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<HkdfPrfParameters,
                                       internal::ProtoParametersSerialization>;

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
    const internal::ProtoParametersSerialization& serialization) {
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

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
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

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixType::RAW, proto_key_format.SerializeAsString());
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

}  // namespace

util::Status RegisterHkdfPrfProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(&HkdfPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersSerializer(&HkdfPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  return util::OkStatus();
}
}  // namespace tink
}  // namespace crypto
