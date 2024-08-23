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

#include "tink/prf/hmac_prf_proto_serialization.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/hmac_prf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HmacPrfKeyFormat;
using ::google::crypto::tink::OutputPrefixType;

using HmacPrfProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   HmacPrfParameters>;
using HmacPrfProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<HmacPrfParameters,
                                       internal::ProtoParametersSerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.HmacPrfKey";

util::StatusOr<HmacPrfParameters::HashType> ToHashType(HashType hash_type) {
  switch (hash_type) {
    case HashType::SHA1:
      return HmacPrfParameters::HashType::kSha1;
    case HashType::SHA224:
      return HmacPrfParameters::HashType::kSha224;
    case HashType::SHA256:
      return HmacPrfParameters::HashType::kSha256;
    case HashType::SHA384:
      return HmacPrfParameters::HashType::kSha384;
    case HashType::SHA512:
      return HmacPrfParameters::HashType::kSha512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HashType");
  }
}

util::StatusOr<HashType> ToProtoHashType(
    HmacPrfParameters::HashType hash_type) {
  switch (hash_type) {
    case HmacPrfParameters::HashType::kSha1:
      return HashType::SHA1;
    case HmacPrfParameters::HashType::kSha224:
      return HashType::SHA224;
    case HmacPrfParameters::HashType::kSha256:
      return HashType::SHA256;
    case HmacPrfParameters::HashType::kSha384:
      return HashType::SHA384;
    case HmacPrfParameters::HashType::kSha512:
      return HashType::SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HmacPrfParameters::HashType");
  }
}

util::StatusOr<HmacPrfParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing HmacPrfParameters.");
  }
  if (serialization.GetKeyTemplate().output_prefix_type() !=
      OutputPrefixType::RAW) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Output prefix type must be RAW for HmacPrfParameters.");
  }

  HmacPrfKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse HmacPrfKeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<HmacPrfParameters::HashType> hash_type =
      ToHashType(proto_key_format.params().hash());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  return HmacPrfParameters::Create(proto_key_format.key_size(), *hash_type);
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const HmacPrfParameters& parameters) {
  util::StatusOr<HashType> proto_hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!proto_hash_type.ok()) {
    return proto_hash_type.status();
  }

  HmacPrfKeyFormat proto_key_format;
  proto_key_format.set_version(0);
  proto_key_format.set_key_size(parameters.KeySizeInBytes());
  proto_key_format.mutable_params()->set_hash(*proto_hash_type);

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixType::RAW, proto_key_format.SerializeAsString());
}

HmacPrfProtoParametersParserImpl& HmacPrfProtoParametersParser() {
  static auto* parser =
      new HmacPrfProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return *parser;
}

HmacPrfProtoParametersSerializerImpl& HmacPrfProtoParametersSerializer() {
  static auto* serializer =
      new HmacPrfProtoParametersSerializerImpl(kTypeUrl, SerializeParameters);
  return *serializer;
}

}  // namespace

util::Status RegisterHmacPrfProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(&HmacPrfProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersSerializer(&HmacPrfProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  return status;
}

}  // namespace tink
}  // namespace crypto
