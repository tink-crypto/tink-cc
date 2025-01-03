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

#include "tink/aead/internal/legacy_kms_envelope_aead_proto_serialization_impl.h"

#include <memory>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aead_parameters.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/aead/legacy_kms_envelope_aead_key.h"
#include "tink/aead/legacy_kms_envelope_aead_parameters.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/internal/global_serialization_registry.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/parameters.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/kms_envelope.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::util::SecretData;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::KmsEnvelopeAeadKey;
using ::google::crypto::tink::KmsEnvelopeAeadKeyFormat;
using ::google::crypto::tink::OutputPrefixType;

using LegacyKmsEnvelopeAeadProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization,
                         LegacyKmsEnvelopeAeadParameters>;
using LegacyKmsEnvelopeAeadProtoParametersSerializerImpl =
    ParametersSerializerImpl<LegacyKmsEnvelopeAeadParameters,
                             ProtoParametersSerialization>;
using LegacyKmsEnvelopeAeadProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, LegacyKmsEnvelopeAeadKey>;
using LegacyKmsEnvelopeAeadProtoKeySerializerImpl =
    KeySerializerImpl<LegacyKmsEnvelopeAeadKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";

util::StatusOr<LegacyKmsEnvelopeAeadParameters::Variant> ToVariant(
    OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixType::RAW:
      return LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix;
    case OutputPrefixType::TINK:
      return LegacyKmsEnvelopeAeadParameters::Variant::kTink;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not determine LegacyKmsEnvelopeAeadParameters::Variant");
  }
}

util::StatusOr<OutputPrefixType> ToOutputPrefixType(
    LegacyKmsEnvelopeAeadParameters::Variant variant) {
  switch (variant) {
    case LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix:
      return OutputPrefixType::RAW;
    case LegacyKmsEnvelopeAeadParameters::Variant::kTink:
      return OutputPrefixType::TINK;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine output prefix type");
  }
}

util::StatusOr<std::unique_ptr<Parameters>> ParametersFromKeyTemplate(
    const KeyTemplate& key_template) {
  util::StatusOr<ProtoParametersSerialization> proto_params_serialization =
      ProtoParametersSerialization::Create(key_template);
  if (!proto_params_serialization.ok()) {
    return proto_params_serialization.status();
  }
  return GlobalSerializationRegistry().ParseParameters(
      *proto_params_serialization);
}

util::StatusOr<KeyTemplate> ParametersToKeyTemplate(
    const Parameters& parameters) {
  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      GlobalSerializationRegistry()
          .SerializeParameters<ProtoParametersSerialization>(parameters);
  if (!serialization.ok()) {
    return serialization.status();
  }

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  if (proto_serialization == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to serialize proto parameters.");
  }

  return proto_serialization->GetKeyTemplate();
}

util::StatusOr<LegacyKmsEnvelopeAeadParameters> GetParametersFromKeyFormat(
    const KmsEnvelopeAeadKeyFormat& proto_key_format,
    OutputPrefixType output_prefix_type) {
  util::StatusOr<LegacyKmsEnvelopeAeadParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  KeyTemplate raw_dek_template = proto_key_format.dek_template();
  raw_dek_template.set_output_prefix_type(OutputPrefixType::RAW);
  util::StatusOr<std::unique_ptr<Parameters>> dek_parameters =
      ParametersFromKeyTemplate(raw_dek_template);
  if (!dek_parameters.ok()) {
    return dek_parameters.status();
  }

  const AeadParameters* aead_parameters =
      dynamic_cast<const AeadParameters*>(dek_parameters->get());
  if (aead_parameters == nullptr) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Non-AEAD parameters stored in the `dek_template` field.");
  }

  LegacyKmsEnvelopeAeadParameters::DekParsingStrategy dek_parsing_strategy;
  if (typeid(*aead_parameters) == typeid(AesCtrHmacAeadParameters)) {
    dek_parsing_strategy =
        LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesCtrHmac;
  } else if (typeid(*aead_parameters) == typeid(AesEaxParameters)) {
    dek_parsing_strategy =
        LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesEax;
  } else if (typeid(*aead_parameters) == typeid(AesGcmParameters)) {
    dek_parsing_strategy =
        LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesGcm;
  } else if (typeid(*aead_parameters) == typeid(AesGcmSivParameters)) {
    dek_parsing_strategy =
        LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesGcmSiv;
  } else if (typeid(*aead_parameters) == typeid(XChaCha20Poly1305Parameters)) {
    dek_parsing_strategy = LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
        kAssumeXChaCha20Poly1305;
  } else {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        ("Unsupported DEK parameters when parsing "
                         "LegacyKmsEnvelopeAeadParameters."));
  }

  return LegacyKmsEnvelopeAeadParameters::Create(proto_key_format.kek_uri(),
                                                 *variant, dek_parsing_strategy,
                                                 *aead_parameters);
}

util::StatusOr<LegacyKmsEnvelopeAeadParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing LegacyKmsEnvelopeAeadParameters.");
  }

  KmsEnvelopeAeadKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(
          serialization.GetKeyTemplate().value())) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse KmsEnvelopeAeadKeyFormat proto");
  }

  return GetParametersFromKeyFormat(
      proto_key_format, serialization.GetKeyTemplate().output_prefix_type());
}

util::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const LegacyKmsEnvelopeAeadParameters& parameters) {
  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  util::StatusOr<KeyTemplate> dek_key_template =
      ParametersToKeyTemplate(parameters.GetDekParameters());
  if (!dek_key_template.ok()) {
    return dek_key_template.status();
  }

  KmsEnvelopeAeadKeyFormat proto_key_format;
  proto_key_format.set_kek_uri(parameters.GetKeyUri());
  *proto_key_format.mutable_dek_template() = *dek_key_template;

  return ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

util::StatusOr<LegacyKmsEnvelopeAeadKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing LegacyKmsEnvelopeAeadKey.");
  }
  KmsEnvelopeAeadKey proto_key;
  if (!proto_key.ParseFromString(serialization.SerializedKeyProto().GetSecret(
          GetInsecureSecretKeyAccessInternal()))) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse KmsEnvelopeAeadKey proto");
  }
  if (proto_key.version() != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  util::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      GetParametersFromKeyFormat(proto_key.params(),
                                 serialization.GetOutputPrefixType());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return LegacyKmsEnvelopeAeadKey::Create(*parameters,
                                          serialization.IdRequirement());
}

util::StatusOr<ProtoKeySerialization> SerializeKey(
    const LegacyKmsEnvelopeAeadKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  util::StatusOr<KeyTemplate> dek_key_template =
      ParametersToKeyTemplate(key.GetParameters().GetDekParameters());
  if (!dek_key_template.ok()) {
    return dek_key_template.status();
  }

  KmsEnvelopeAeadKeyFormat proto_key_format;
  proto_key_format.set_kek_uri(key.GetParameters().GetKeyUri());
  *proto_key_format.mutable_dek_template() = *dek_key_template;
  KmsEnvelopeAeadKey proto_key;
  proto_key.set_version(0);
  *proto_key.mutable_params() = proto_key_format;

  util::StatusOr<OutputPrefixType> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output = RestrictedData(
      proto_key.SerializeAsString(), GetInsecureSecretKeyAccessInternal());

  return ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, google::crypto::tink::KeyData::REMOTE,
      *output_prefix_type, key.GetIdRequirement());
}

LegacyKmsEnvelopeAeadProtoParametersParserImpl*
LegacyKmsEnvelopeAeadProtoParametersParser() {
  static auto* parser = new LegacyKmsEnvelopeAeadProtoParametersParserImpl(
      kTypeUrl, ParseParameters);
  return parser;
}

LegacyKmsEnvelopeAeadProtoParametersSerializerImpl*
LegacyKmsEnvelopeAeadProtoParametersSerializer() {
  static auto* serializer =
      new LegacyKmsEnvelopeAeadProtoParametersSerializerImpl(
          kTypeUrl, SerializeParameters);
  return serializer;
}

LegacyKmsEnvelopeAeadProtoKeyParserImpl* LegacyKmsEnvelopeAeadProtoKeyParser() {
  static auto* parser =
      new LegacyKmsEnvelopeAeadProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

LegacyKmsEnvelopeAeadProtoKeySerializerImpl*
LegacyKmsEnvelopeAeadProtoKeySerializer() {
  static auto* serializer =
      new LegacyKmsEnvelopeAeadProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

util::Status RegisterLegacyKmsEnvelopeAeadProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  util::Status status = registry.RegisterParametersParser(
      LegacyKmsEnvelopeAeadProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      LegacyKmsEnvelopeAeadProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(LegacyKmsEnvelopeAeadProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(
      LegacyKmsEnvelopeAeadProtoKeySerializer());
}

util::Status RegisterLegacyKmsEnvelopeAeadProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  util::Status status = builder.RegisterParametersParser(
      LegacyKmsEnvelopeAeadProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterParametersSerializer(
      LegacyKmsEnvelopeAeadProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(LegacyKmsEnvelopeAeadProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(
      LegacyKmsEnvelopeAeadProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
