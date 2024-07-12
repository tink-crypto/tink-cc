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

#include "tink/streamingaead/aes_ctr_hmac_streaming_proto_serialization.h"

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_ctr_hmac_streaming.pb.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::AesCtrHmacStreamingKeyFormat;
using ::google::crypto::tink::AesCtrHmacStreamingParams;
using ::google::crypto::tink::OutputPrefixType;

using AesCtrHmacStreamingProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   AesCtrHmacStreamingParameters>;
using AesCtrHmacStreamingProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<AesCtrHmacStreamingParameters,
                                       internal::ProtoParametersSerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";

util::StatusOr<AesCtrHmacStreamingParameters::HashType> FromProtoHashType(
    google::crypto::tink::HashType hash_type) {
  switch (hash_type) {
    case google::crypto::tink::HashType::SHA1:
      return AesCtrHmacStreamingParameters::HashType::kSha1;
    case google::crypto::tink::HashType::SHA256:
      return AesCtrHmacStreamingParameters::HashType::kSha256;
    case google::crypto::tink::HashType::SHA512:
      return AesCtrHmacStreamingParameters::HashType::kSha512;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported proto hash type: ", hash_type));
  }
}

util::StatusOr<google::crypto::tink::HashType> ToProtoHashType(
    AesCtrHmacStreamingParameters::HashType hash_type) {
  switch (hash_type) {
    case AesCtrHmacStreamingParameters::HashType::kSha1:
      return google::crypto::tink::HashType::SHA1;
    case AesCtrHmacStreamingParameters::HashType::kSha256:
      return google::crypto::tink::HashType::SHA256;
    case AesCtrHmacStreamingParameters::HashType::kSha512:
      return google::crypto::tink::HashType::SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported hash type: ", hash_type));
  }
}

util::StatusOr<AesCtrHmacStreamingParameters> FromProtoParams(
    const AesCtrHmacStreamingParams& proto_params, int key_size) {
  if (!proto_params.has_hmac_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Missing AesCtrHmacStreamingParams.hmac_params.");
  }
  util::StatusOr<AesCtrHmacStreamingParameters::HashType> hkdf_hash_type =
      FromProtoHashType(proto_params.hkdf_hash_type());
  if (!hkdf_hash_type.ok()) {
    return hkdf_hash_type.status();
  }
  util::StatusOr<AesCtrHmacStreamingParameters::HashType> hmac_hash_type =
      FromProtoHashType(proto_params.hmac_params().hash());
  if (!hmac_hash_type.ok()) {
    return hmac_hash_type.status();
  }

  return AesCtrHmacStreamingParameters::Builder()
      .SetKeySizeInBytes(key_size)
      .SetDerivedKeySizeInBytes(proto_params.derived_key_size())
      .SetHkdfHashType(*hkdf_hash_type)
      .SetHmacHashType(*hmac_hash_type)
      .SetHmacTagSizeInBytes(proto_params.hmac_params().tag_size())
      .SetCiphertextSegmentSizeInBytes(proto_params.ciphertext_segment_size())
      .Build();
}

util::StatusOr<AesCtrHmacStreamingParams> ToProtoParams(
    const AesCtrHmacStreamingParameters& parameters) {
  util::StatusOr<google::crypto::tink::HashType> hkdf_hash_type =
      ToProtoHashType(parameters.HkdfHashType());
  if (!hkdf_hash_type.ok()) {
    return hkdf_hash_type.status();
  }
  util::StatusOr<google::crypto::tink::HashType> hmac_hash_type =
      ToProtoHashType(parameters.HmacHashType());
  if (!hmac_hash_type.ok()) {
    return hmac_hash_type.status();
  }

  AesCtrHmacStreamingParams params;
  params.set_derived_key_size(parameters.DerivedKeySizeInBytes());
  params.set_hkdf_hash_type(*hkdf_hash_type);
  params.mutable_hmac_params()->set_hash(*hmac_hash_type);
  params.mutable_hmac_params()->set_tag_size(parameters.HmacTagSizeInBytes());
  params.set_ciphertext_segment_size(parameters.CiphertextSegmentSizeInBytes());
  return params;
}

util::StatusOr<AesCtrHmacStreamingParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing AesCtrHmacStreamingParameters.");
  }
  AesCtrHmacStreamingKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse AesCtrHmacStreamingKeyFormat proto.");
  }
  if (proto_key_format.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Parsing AesCtrHmacStreamingKeyFormat failed: only "
                        "version 0 is accepted.");
  }

  if (!proto_key_format.has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Missing AesCtrHmacStreamingParams.");
  }
  return FromProtoParams(proto_key_format.params(),
                         proto_key_format.key_size());
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const AesCtrHmacStreamingParameters& parameters) {
  AesCtrHmacStreamingKeyFormat format;
  format.set_version(0);
  format.set_key_size(parameters.KeySizeInBytes());
  util::StatusOr<AesCtrHmacStreamingParams> proto_params =
      ToProtoParams(parameters);
  if (!proto_params.ok()) {
    return proto_params.status();
  }
  *format.mutable_params() = *proto_params;

  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, OutputPrefixType::RAW, format.SerializeAsString());
}

AesCtrHmacStreamingProtoParametersParserImpl*
AesCtrHmacStreamingProtoParametersParser() {
  static auto* parser = new AesCtrHmacStreamingProtoParametersParserImpl(
      kTypeUrl, ParseParameters);
  return parser;
}

AesCtrHmacStreamingProtoParametersSerializerImpl*
AesCtrHmacStreamingProtoParametersSerializer() {
  static auto* serializer =
      new AesCtrHmacStreamingProtoParametersSerializerImpl(kTypeUrl,
                                                           SerializeParameters);
  return serializer;
}

}  // namespace

util::Status RegisterAesCtrHmacStreamingProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(AesCtrHmacStreamingProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterParametersSerializer(
          AesCtrHmacStreamingProtoParametersSerializer());
}

}  // namespace tink
}  // namespace crypto
