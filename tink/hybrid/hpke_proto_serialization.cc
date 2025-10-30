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

#include <array>
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
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_owning_fields.h"
#include "tink/internal/proto_parser_secret_data_owning_field.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::proto_parsing::EnumOwningField;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageOwningField;
using ::crypto::tink::internal::proto_parsing::OwningBytesField;
using ::crypto::tink::internal::proto_parsing::OwningField;
using ::crypto::tink::internal::proto_parsing::SecretDataOwningField;
using ::crypto::tink::internal::proto_parsing::Uint32OwningField;

bool HpkeKemEnumIsValid(int value) { return value >= 0 && value <= 7; }

// Proto enum com.google.crypto.tink.HpkeKem.
enum class HpkeKemEnum : uint32_t {
  kUnknown = 0,
  kDhkemX25519HkdfSha256,
  kDhkemP256HkdfSha256,
  kDhkemP384HkdfSha384,
  kDhkemP521HkdfSha512,
  kXWing,
  kMlKem768,
  kMlKem1024,
};

bool HpkeKdfEnumIsValid(int value) { return value >= 0 && value <= 3; }

// Proto enum com.google.crypto.tink.HpkeKdf.
enum class HpkeKdfEnum : uint32_t {
  kUnknown = 0,
  kHkdfSha256,
  kHkdfSha384,
  kHkdfSha512,
};

bool HpkeAeadEnumIsValid(int value) { return value >= 0 && value <= 3; }

// Proto enum com.google.crypto.tink.HpkeAead.
enum class HpkeAeadEnum : uint32_t {
  kUnknown = 0,
  kAes128Gcm,
  kAes256Gcm,
  kChaCha20Poly1305,
};

class ProtoHpkeParams : public Message<ProtoHpkeParams> {
 public:
  ProtoHpkeParams() = default;
  using Message::SerializeAsString;

  HpkeKemEnum kem() const { return kem_.value(); }
  void set_kem(HpkeKemEnum kem) { kem_.set_value(kem); }

  HpkeKdfEnum kdf() const { return kdf_.value(); }
  void set_kdf(HpkeKdfEnum kdf) { kdf_.set_value(kdf); }

  HpkeAeadEnum aead() const { return aead_.value(); }
  void set_aead(HpkeAeadEnum aead) { aead_.set_value(aead); }

  std::array<const OwningField*, 3> GetFields() const {
    return {&kem_, &kdf_, &aead_};
  }

 private:
  EnumOwningField<HpkeKemEnum> kem_{1, &HpkeKemEnumIsValid};
  EnumOwningField<HpkeKdfEnum> kdf_{2, &HpkeKdfEnumIsValid};
  EnumOwningField<HpkeAeadEnum> aead_{3, &HpkeAeadEnumIsValid};
};

class ProtoHpkePublicKey : public Message<ProtoHpkePublicKey> {
 public:
  ProtoHpkePublicKey() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const ProtoHpkeParams& params() const { return params_.value(); }
  ProtoHpkeParams* mutable_params() { return params_.mutable_value(); }

  const std::string& public_key() const { return public_key_.value(); }
  void set_public_key(absl::string_view public_key) {
    public_key_.set_value(public_key);
  }

  std::array<const OwningField*, 3> GetFields() const {
    return {&version_, &params_, &public_key_};
  }

 private:
  Uint32OwningField version_{1};
  MessageOwningField<ProtoHpkeParams> params_{2};
  OwningBytesField<std::string> public_key_{3};
};

class ProtoHpkePrivateKey : public Message<ProtoHpkePrivateKey> {
 public:
  ProtoHpkePrivateKey() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const ProtoHpkePublicKey& public_key() const { return public_key_.value(); }
  ProtoHpkePublicKey* mutable_public_key() {
    return public_key_.mutable_value();
  }

  const SecretData& private_key() const { return private_key_.value(); }
  void set_private_key(SecretData private_key) {
    *private_key_.mutable_value() = private_key;
  }

  std::array<const OwningField*, 3> GetFields() const {
    return {&version_, &public_key_, &private_key_};
  }

 private:
  Uint32OwningField version_{1};
  MessageOwningField<ProtoHpkePublicKey> public_key_{2};
  SecretDataOwningField private_key_{3};
};

class ProtoHpkeKeyFormat : public Message<ProtoHpkeKeyFormat> {
 public:
  ProtoHpkeKeyFormat() = default;
  using Message::SerializeAsString;

  const ProtoHpkeParams& params() const { return params_.value(); }
  ProtoHpkeParams* mutable_params() { return params_.mutable_value(); }

  std::array<const OwningField*, 1> GetFields() const { return {&params_}; }

 private:
  MessageOwningField<ProtoHpkeParams> params_{1};
};

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

absl::StatusOr<HpkeParameters::Variant> ToVariant(
    internal::OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case internal::OutputPrefixTypeEnum::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case internal::OutputPrefixTypeEnum::kCrunchy:
      return HpkeParameters::Variant::kCrunchy;
    case internal::OutputPrefixTypeEnum::kRaw:
      return HpkeParameters::Variant::kNoPrefix;
    case internal::OutputPrefixTypeEnum::kTink:
      return HpkeParameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine HpkeParameters::Variant");
  }
}

absl::StatusOr<internal::OutputPrefixTypeEnum> ToOutputPrefixType(
    HpkeParameters::Variant variant) {
  switch (variant) {
    case HpkeParameters::Variant::kCrunchy:
      return internal::OutputPrefixTypeEnum::kCrunchy;
    case HpkeParameters::Variant::kNoPrefix:
      return internal::OutputPrefixTypeEnum::kRaw;
    case HpkeParameters::Variant::kTink:
      return internal::OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type.");
  }
}

absl::StatusOr<HpkeParameters::KemId> ToKemId(HpkeKemEnum kem) {
  switch (kem) {
    case HpkeKemEnum::kDhkemP256HkdfSha256:
      return HpkeParameters::KemId::kDhkemP256HkdfSha256;
    case HpkeKemEnum::kDhkemP384HkdfSha384:
      return HpkeParameters::KemId::kDhkemP384HkdfSha384;
    case HpkeKemEnum::kDhkemP521HkdfSha512:
      return HpkeParameters::KemId::kDhkemP521HkdfSha512;
    case HpkeKemEnum::kDhkemX25519HkdfSha256:
      return HpkeParameters::KemId::kDhkemX25519HkdfSha256;
    case HpkeKemEnum::kXWing:
      return HpkeParameters::KemId::kXWing;
    case HpkeKemEnum::kMlKem768:
      return HpkeParameters::KemId::kMlKem768;
    case HpkeKemEnum::kMlKem1024:
      return HpkeParameters::KemId::kMlKem1024;
    default:
      return absl::InvalidArgumentError("Could not determine KEM.");
  }
}

absl::StatusOr<HpkeKemEnum> FromKemId(HpkeParameters::KemId kem_id) {
  switch (kem_id) {
    case HpkeParameters::KemId::kDhkemP256HkdfSha256:
      return HpkeKemEnum::kDhkemP256HkdfSha256;
    case HpkeParameters::KemId::kDhkemP384HkdfSha384:
      return HpkeKemEnum::kDhkemP384HkdfSha384;
    case HpkeParameters::KemId::kDhkemP521HkdfSha512:
      return HpkeKemEnum::kDhkemP521HkdfSha512;
    case HpkeParameters::KemId::kDhkemX25519HkdfSha256:
      return HpkeKemEnum::kDhkemX25519HkdfSha256;
    case HpkeParameters::KemId::kXWing:
      return HpkeKemEnum::kXWing;
    case HpkeParameters::KemId::kMlKem768:
      return HpkeKemEnum::kMlKem768;
    case HpkeParameters::KemId::kMlKem1024:
      return HpkeKemEnum::kMlKem1024;
    default:
      return absl::InvalidArgumentError("Could not determine KEM.");
  }
}

absl::StatusOr<HpkeParameters::KdfId> ToKdfId(HpkeKdfEnum kdf) {
  switch (kdf) {
    case HpkeKdfEnum::kHkdfSha256:
      return HpkeParameters::KdfId::kHkdfSha256;
    case HpkeKdfEnum::kHkdfSha384:
      return HpkeParameters::KdfId::kHkdfSha384;
    case HpkeKdfEnum::kHkdfSha512:
      return HpkeParameters::KdfId::kHkdfSha512;
    default:
      return absl::InvalidArgumentError("Could not determine KDF.");
  }
}

absl::StatusOr<HpkeKdfEnum> FromKdfId(HpkeParameters::KdfId kdf_id) {
  switch (kdf_id) {
    case HpkeParameters::KdfId::kHkdfSha256:
      return HpkeKdfEnum::kHkdfSha256;
    case HpkeParameters::KdfId::kHkdfSha384:
      return HpkeKdfEnum::kHkdfSha384;
    case HpkeParameters::KdfId::kHkdfSha512:
      return HpkeKdfEnum::kHkdfSha512;
    default:
      return absl::InvalidArgumentError("Could not determine KDF.");
  }
}

absl::StatusOr<HpkeParameters::AeadId> ToAeadId(HpkeAeadEnum aead) {
  switch (aead) {
    case HpkeAeadEnum::kAes128Gcm:
      return HpkeParameters::AeadId::kAesGcm128;
    case HpkeAeadEnum::kAes256Gcm:
      return HpkeParameters::AeadId::kAesGcm256;
    case HpkeAeadEnum::kChaCha20Poly1305:
      return HpkeParameters::AeadId::kChaCha20Poly1305;
    default:
      return absl::InvalidArgumentError("Could not determine AEAD.");
  }
}

absl::StatusOr<HpkeAeadEnum> FromAeadId(HpkeParameters::AeadId aead_id) {
  switch (aead_id) {
    case HpkeParameters::AeadId::kAesGcm128:
      return HpkeAeadEnum::kAes128Gcm;
    case HpkeParameters::AeadId::kAesGcm256:
      return HpkeAeadEnum::kAes256Gcm;
    case HpkeParameters::AeadId::kChaCha20Poly1305:
      return HpkeAeadEnum::kChaCha20Poly1305;
    default:
      return absl::InvalidArgumentError("Could not determine AEAD.");
  }
}

absl::StatusOr<HpkeParameters> ToParameters(
    internal::OutputPrefixTypeEnum output_prefix_type,
    const ProtoHpkeParams& params) {
  absl::StatusOr<HpkeParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<HpkeParameters::KemId> kem_id = ToKemId(params.kem());
  if (!kem_id.ok()) {
    return kem_id.status();
  }

  absl::StatusOr<HpkeParameters::KdfId> kdf_id = ToKdfId(params.kdf());
  if (!kdf_id.ok()) {
    return kdf_id.status();
  }

  absl::StatusOr<HpkeParameters::AeadId> aead_id = ToAeadId(params.aead());
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

absl::StatusOr<ProtoHpkeParams> FromParameters(HpkeParameters parameters) {
  absl::StatusOr<HpkeKemEnum> kem = FromKemId(parameters.GetKemId());
  if (!kem.ok()) {
    return kem.status();
  }

  absl::StatusOr<HpkeKdfEnum> kdf = FromKdfId(parameters.GetKdfId());
  if (!kdf.ok()) {
    return kdf.status();
  }

  absl::StatusOr<HpkeAeadEnum> aead = FromAeadId(parameters.GetAeadId());
  if (!aead.ok()) {
    return aead.status();
  }

  ProtoHpkeParams params;
  params.set_kem(*kem);
  params.set_kdf(*kdf);
  params.set_aead(*aead);

  return params;
}

absl::StatusOr<HpkeParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  const internal::ProtoKeyTemplate& key_template =
      serialization.GetProtoKeyTemplate();
  if (key_template.type_url() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing HpkeParameters.");
  }

  ProtoHpkeKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError("Failed to parse HpkeKeyFormat proto");
  }

  return ToParameters(key_template.output_prefix_type(),
                      proto_key_format.params());
}

absl::StatusOr<HpkePublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing HpkePublicKey.");
  }

  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  ProtoHpkePublicKey proto_key;
  if (!proto_key.ParseFromString(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()))) {
    return absl::InvalidArgumentError("Failed to parse HpkePublicKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<HpkeParameters> parameters =
      ToParameters(serialization.GetOutputPrefixTypeEnum(), proto_key.params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return HpkePublicKey::Create(*parameters, proto_key.public_key(),
                               serialization.IdRequirement(),
                               GetPartialKeyAccess());
}

absl::StatusOr<HpkePrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing HpkePrivateKey.");
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  ProtoHpkePrivateKey proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse HpkePrivateKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  if (proto_key.public_key().version() != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 public keys are accepted.");
  }

  absl::StatusOr<HpkeParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixTypeEnum());
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<HpkeParameters> parameters = ToParameters(
      serialization.GetOutputPrefixTypeEnum(), proto_key.public_key().params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, proto_key.public_key().public_key(),
      serialization.IdRequirement(), GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return HpkePrivateKey::Create(*public_key,
                                RestrictedData(proto_key.private_key(), *token),
                                GetPartialKeyAccess());
}

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const HpkeParameters& parameters) {
  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<ProtoHpkeParams> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }
  ProtoHpkeKeyFormat proto_key_format;
  *proto_key_format.mutable_params() = *params;

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type,
      proto_key_format.SerializeAsString());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const HpkePublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<ProtoHpkeParams> params = FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  ProtoHpkePublicKey proto_key;
  proto_key.set_version(0);
  *proto_key.mutable_params() = *params;
  proto_key.set_public_key(key.GetPublicKeyBytes(GetPartialKeyAccess()));

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output = RestrictedData(
      proto_key.SerializeAsString(), InsecureSecretKeyAccess::Get());
  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl, restricted_output,
      internal::KeyMaterialTypeEnum::kAsymmetricPublic, *output_prefix_type,
      key.GetIdRequirement());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePrivateKey(
    const HpkePrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetPrivateKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  absl::StatusOr<ProtoHpkeParams> params = FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  ProtoHpkePrivateKey proto_key;
  proto_key.mutable_public_key()->set_version(0);
  *proto_key.mutable_public_key()->mutable_params() = *params;
  proto_key.mutable_public_key()->set_public_key(
      key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess()));
  proto_key.set_version(0);
  proto_key.set_private_key(restricted_input->Get(*token));

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl,
      RestrictedData(proto_key.SerializeAsSecretData(), *token),
      internal::KeyMaterialTypeEnum::kAsymmetricPrivate, *output_prefix_type,
      key.GetIdRequirement());
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

absl::Status RegisterHpkeProtoSerialization() {
  absl::Status status =
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
