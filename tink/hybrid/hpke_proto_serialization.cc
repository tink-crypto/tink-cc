// Copyright 2023 Google LLC
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

#include "tink/hybrid/hpke_proto_serialization.h"

#include <cstdint>
#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
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
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;

bool HpkeKemIsValid(int v) {
  return ::google::crypto::tink::HpkeKem_IsValid(v);
}

bool HpkeKdfIsValid(int v) {
  return ::google::crypto::tink::HpkeKdf_IsValid(v);
}

bool HpkeAeadIsValid(int v) {
  return ::google::crypto::tink::HpkeAead_IsValid(v);
}

struct HpkeParamsStruct {
  google::crypto::tink::HpkeKem kem;
  google::crypto::tink::HpkeKdf kdf;
  google::crypto::tink::HpkeAead aead;
};

struct HpkePublicKeyStruct {
  uint32_t version;
  HpkeParamsStruct params;
  std::string public_key;
};

struct HpkePrivateKeyStruct {
  uint32_t version;
  HpkePublicKeyStruct public_key;
  util::SecretData private_key;
};

struct HpkeKeyFormatStruct {
  HpkeParamsStruct params;
};

ProtoParser<HpkeParamsStruct> CreateParamParser() {
  return ProtoParserBuilder<HpkeParamsStruct>()
      .AddEnumField(1, &HpkeParamsStruct::kem, &HpkeKemIsValid)
      .AddEnumField(2, &HpkeParamsStruct::kdf, &HpkeKdfIsValid)
      .AddEnumField(3, &HpkeParamsStruct::aead, &HpkeAeadIsValid)
      .BuildOrDie();
}

ProtoParser<HpkePublicKeyStruct> CreatePublicKeyParser() {
  return ProtoParserBuilder<HpkePublicKeyStruct>()
      .AddUint32Field(1, &HpkePublicKeyStruct::version)
      .AddMessageField(2, &HpkePublicKeyStruct::params,
                       CreateParamParser())
      .AddBytesStringField(3, &HpkePublicKeyStruct::public_key)
      .BuildOrDie();
}

const ProtoParser<HpkePublicKeyStruct>& GetPublicKeyParser() {
  static ProtoParser<HpkePublicKeyStruct>* parser =
      new ProtoParser<HpkePublicKeyStruct>(CreatePublicKeyParser());
  return *parser;
}

ProtoParser<HpkePrivateKeyStruct> CreatePrivateKeyParser() {
  return ProtoParserBuilder<HpkePrivateKeyStruct>()
      .AddUint32Field(1, &HpkePrivateKeyStruct::version)
      .AddMessageField(2, &HpkePrivateKeyStruct::public_key,
                       CreatePublicKeyParser())
      .AddBytesSecretDataField(3, &HpkePrivateKeyStruct::private_key)
      .BuildOrDie();
}

const ProtoParser<HpkePrivateKeyStruct>& GetPrivateKeyParser() {
  static ProtoParser<HpkePrivateKeyStruct>* parser =
      new ProtoParser<HpkePrivateKeyStruct>(CreatePrivateKeyParser());
  return *parser;
}

ProtoParser<HpkeKeyFormatStruct> CreateKeyFormatParser() {
  return ProtoParserBuilder<HpkeKeyFormatStruct>()
      .AddMessageField(1, &HpkeKeyFormatStruct::params,
                       CreateParamParser())
      .BuildOrDie();
}

const ProtoParser<HpkeKeyFormatStruct>& GetKeyFormatParser() {
  static ProtoParser<HpkeKeyFormatStruct>* parser =
      new ProtoParser<HpkeKeyFormatStruct>(CreateKeyFormatParser());
  return *parser;
}

using HpkeProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   HpkeParameters>;
using HpkeProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<HpkeParameters,
                                       internal::ProtoParametersSerialization>;
using HpkeProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, HpkePublicKey>;
using HpkeProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<HpkePublicKey, internal::ProtoKeySerialization>;
using HpkeProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, HpkePrivateKey>;
using HpkeProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<HpkePrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.HpkePublicKey";
const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.HpkePrivateKey";

util::StatusOr<HpkeParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::LEGACY:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixType::CRUNCHY:
      return HpkeParameters::Variant::kCrunchy;
    case OutputPrefixType::RAW:
      return HpkeParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return HpkeParameters::Variant::kTink;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine HpkeParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    HpkeParameters::Variant variant) {
  switch (variant) {
    case HpkeParameters::Variant::kCrunchy:
      return OutputPrefixType::CRUNCHY;
    case HpkeParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case HpkeParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type.");
  }
}

util::StatusOr<HpkeParameters::KemId> ToKemId(HpkeKem kem) {
  switch (kem) {
    case HpkeKem::DHKEM_P256_HKDF_SHA256:
      return HpkeParameters::KemId::kDhkemP256HkdfSha256;
    case HpkeKem::DHKEM_P384_HKDF_SHA384:
      return HpkeParameters::KemId::kDhkemP384HkdfSha384;
    case HpkeKem::DHKEM_P521_HKDF_SHA512:
      return HpkeParameters::KemId::kDhkemP521HkdfSha512;
    case HpkeKem::DHKEM_X25519_HKDF_SHA256:
      return HpkeParameters::KemId::kDhkemX25519HkdfSha256;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine KEM.");
  }
}

util::StatusOr<HpkeKem> FromKemId(HpkeParameters::KemId kem_id) {
  switch (kem_id) {
    case HpkeParameters::KemId::kDhkemP256HkdfSha256:
      return HpkeKem::DHKEM_P256_HKDF_SHA256;
    case HpkeParameters::KemId::kDhkemP384HkdfSha384:
      return HpkeKem::DHKEM_P384_HKDF_SHA384;
    case HpkeParameters::KemId::kDhkemP521HkdfSha512:
      return HpkeKem::DHKEM_P521_HKDF_SHA512;
    case HpkeParameters::KemId::kDhkemX25519HkdfSha256:
      return HpkeKem::DHKEM_X25519_HKDF_SHA256;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine KEM.");
  }
}

util::StatusOr<HpkeParameters::KdfId> ToKdfId(HpkeKdf kdf) {
  switch (kdf) {
    case HpkeKdf::HKDF_SHA256:
      return HpkeParameters::KdfId::kHkdfSha256;
    case HpkeKdf::HKDF_SHA384:
      return HpkeParameters::KdfId::kHkdfSha384;
    case HpkeKdf::HKDF_SHA512:
      return HpkeParameters::KdfId::kHkdfSha512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine KDF.");
  }
}

util::StatusOr<HpkeKdf> FromKdfId(HpkeParameters::KdfId kdf_id) {
  switch (kdf_id) {
    case HpkeParameters::KdfId::kHkdfSha256:
      return HpkeKdf::HKDF_SHA256;
    case HpkeParameters::KdfId::kHkdfSha384:
      return HpkeKdf::HKDF_SHA384;
    case HpkeParameters::KdfId::kHkdfSha512:
      return HpkeKdf::HKDF_SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine KDF.");
  }
}

util::StatusOr<HpkeParameters::AeadId> ToAeadId(HpkeAead aead) {
  switch (aead) {
    case HpkeAead::AES_128_GCM:
      return HpkeParameters::AeadId::kAesGcm128;
    case HpkeAead::AES_256_GCM:
      return HpkeParameters::AeadId::kAesGcm256;
    case HpkeAead::CHACHA20_POLY1305:
      return HpkeParameters::AeadId::kChaCha20Poly1305;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine AEAD.");
  }
}

util::StatusOr<HpkeAead> FromAeadId(HpkeParameters::AeadId aead_id) {
  switch (aead_id) {
    case HpkeParameters::AeadId::kAesGcm128:
      return HpkeAead::AES_128_GCM;
    case HpkeParameters::AeadId::kAesGcm256:
      return HpkeAead::AES_256_GCM;
    case HpkeParameters::AeadId::kChaCha20Poly1305:
      return HpkeAead::CHACHA20_POLY1305;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine AEAD.");
  }
}

util::StatusOr<HpkeParameters> ToParameters(
    OutputPrefixType output_prefix_type, const HpkeParamsStruct& params) {
  util::StatusOr<HpkeParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<HpkeParameters::KemId> kem_id = ToKemId(params.kem);
  if (!kem_id.ok()) {
    return kem_id.status();
  }

  util::StatusOr<HpkeParameters::KdfId> kdf_id = ToKdfId(params.kdf);
  if (!kdf_id.ok()) {
    return kdf_id.status();
  }

  util::StatusOr<HpkeParameters::AeadId> aead_id = ToAeadId(params.aead);
  if (!aead_id.ok()) {
    return aead_id.status();
  }

  return HpkeParameters::Builder()
      .SetVariant(*variant)
      .SetKemId(*kem_id)
      .SetKdfId(*kdf_id)
      .SetAeadId(*aead_id)
      .Build();
}

util::StatusOr<HpkeParamsStruct> FromParameters(HpkeParameters parameters) {
  util::StatusOr<HpkeKem> kem = FromKemId(parameters.GetKemId());
  if (!kem.ok()) {
    return kem.status();
  }

  util::StatusOr<HpkeKdf> kdf = FromKdfId(parameters.GetKdfId());
  if (!kdf.ok()) {
    return kdf.status();
  }

  util::StatusOr<HpkeAead> aead = FromAeadId(parameters.GetAeadId());
  if (!aead.ok()) {
    return aead.status();
  }

  HpkeParamsStruct params;
  params.kem = *kem;
  params.kdf = *kdf;
  params.aead = *aead;

  return params;
}

util::StatusOr<HpkeParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing HpkeParameters.");
  }

  absl::StatusOr<HpkeKeyFormatStruct> proto_key_format =
      GetKeyFormatParser().Parse(serialization.GetKeyTemplate().value());
  if (!proto_key_format.ok()) {
    return proto_key_format.status();
  }

  return ToParameters(serialization.GetKeyTemplate().output_prefix_type(),
                      proto_key_format->params);
}

util::StatusOr<HpkePublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing HpkePublicKey.");
  }

  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  util::StatusOr<HpkePublicKeyStruct> proto_key = GetPublicKeyParser().Parse(
      restricted_data.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!proto_key.ok()) {
    return proto_key.status();
  }
  if (proto_key->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<HpkeParameters> parameters =
      ToParameters(serialization.GetOutputPrefixType(), proto_key->params);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return HpkePublicKey::Create(*parameters, proto_key->public_key,
                               serialization.IdRequirement(),
                               GetPartialKeyAccess());
}

util::StatusOr<HpkePrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong type URL when parsing HpkePrivateKey.");
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }
  util::StatusOr<HpkePrivateKeyStruct> proto_key = GetPrivateKeyParser().Parse(
      serialization.SerializedKeyProto().GetSecret(*token));
  if (!proto_key.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse HpkePrivateKey proto");
  }
  if (proto_key->version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  if (proto_key->public_key.version != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 public keys are accepted.");
  }

  util::StatusOr<HpkeParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixType());
  if (!variant.ok()) {
    return variant.status();
  }

  util::StatusOr<HpkeParameters> parameters = ToParameters(
      serialization.GetOutputPrefixType(), proto_key->public_key.params);
  if (!parameters.ok()) {
    return parameters.status();
  }

  util::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, proto_key->public_key.public_key,
      serialization.IdRequirement(), GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return HpkePrivateKey::Create(
      *public_key, RestrictedData(proto_key->private_key, *token),
      GetPartialKeyAccess());
}

util::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const HpkeParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<HpkeParamsStruct> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }
  HpkeKeyFormatStruct proto_key_format;
  proto_key_format.params = *params;

  util::StatusOr<std::string> serialized =
      GetKeyFormatParser().SerializeIntoString(proto_key_format);
  if (!serialized.ok()) {
    return serialized.status();
  }

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, *serialized);
}

util::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const HpkePublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<HpkeParamsStruct> params = FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  HpkePublicKeyStruct proto_key;
  proto_key.version = 0;
  proto_key.params = *params;
  proto_key.public_key =
      std::string(key.GetPublicKeyBytes(GetPartialKeyAccess()));

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<std::string> serialized =
      GetPublicKeyParser().SerializeIntoString(proto_key);
  if (!serialized.ok()) {
    return serialized.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*serialized, InsecureSecretKeyAccess::Get());
  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl, restricted_output, KeyData::ASYMMETRIC_PUBLIC,
      *output_prefix_type, key.GetIdRequirement());
}

util::StatusOr<internal::ProtoKeySerialization> SerializePrivateKey(
    const HpkePrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<RestrictedData> restricted_input =
      key.GetPrivateKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }
  if (!token.has_value()) {
    return util::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required");
  }

  util::StatusOr<HpkeParamsStruct> params = FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  HpkePrivateKeyStruct proto_key;
  proto_key.public_key.version = 0;
  proto_key.public_key.params = *params;
  proto_key.public_key.public_key =
      std::string(key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess()));
  proto_key.version = 0;
  proto_key.private_key =
      util::SecretDataFromStringView(restricted_input->GetSecret(*token));

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<util::SecretData> serialized =
      GetPrivateKeyParser().SerializeIntoSecretData(proto_key);
  if (!serialized.ok()) {
    return serialized.status();
  }

  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl, RestrictedData(*serialized, *token),
      KeyData::ASYMMETRIC_PRIVATE, *output_prefix_type, key.GetIdRequirement());
}

HpkeProtoParametersParserImpl* HpkeProtoParametersParser() {
  static auto* parser =
      new HpkeProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return parser;
}

HpkeProtoParametersSerializerImpl* HpkeProtoParametersSerializer() {
  static auto* serializer = new HpkeProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return serializer;
}

HpkeProtoPublicKeyParserImpl* HpkeProtoPublicKeyParser() {
  static auto* parser =
      new HpkeProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return parser;
}

HpkeProtoPublicKeySerializerImpl* HpkeProtoPublicKeySerializer() {
  static auto* serializer =
      new HpkeProtoPublicKeySerializerImpl(SerializePublicKey);
  return serializer;
}

HpkeProtoPrivateKeyParserImpl* HpkeProtoPrivateKeyParser() {
  static auto* parser =
      new HpkeProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return parser;
}

HpkeProtoPrivateKeySerializerImpl* HpkeProtoPrivateKeySerializer() {
  static auto* serializer =
      new HpkeProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return serializer;
}

}  // namespace

util::Status RegisterHpkeProtoSerialization() {
  util::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(HpkeProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(HpkeProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(HpkeProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeySerializer(HpkeProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(HpkeProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(HpkeProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
