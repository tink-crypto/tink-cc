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

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
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
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/parameters.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::BytesField;
using ::crypto::tink::internal::proto_parsing::Field;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageField;
using ::crypto::tink::internal::proto_parsing::Uint32Field;

class KmsEnvelopeAeadKeyFormatTP : public Message {
 public:
  KmsEnvelopeAeadKeyFormatTP() = default;

  const std::string& kek_uri() const { return kek_uri_.value(); }
  void set_kek_uri(absl::string_view value) { kek_uri_.set_value(value); }

  const KeyTemplateTP& dek_template() const { return dek_template_.value(); }
  KeyTemplateTP* mutable_dek_template() {
    return dek_template_.mutable_value();
  }

  // This is OK because this class doesn't contain secret data.
  using Message::SerializeAsString;

 private:
  size_t num_fields() const override { return 2; }
  const Field* field(int i) const override {
    return std::array<const Field*, 2>{&kek_uri_, &dek_template_}[i];
  }
  BytesField kek_uri_{1};
  MessageField<KeyTemplateTP> dek_template_{2};
};

class KmsEnvelopeAeadKeyTP : public Message {
 public:
  KmsEnvelopeAeadKeyTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const KmsEnvelopeAeadKeyFormatTP& params() const { return params_.value(); }
  KmsEnvelopeAeadKeyFormatTP* mutable_params() {
    return params_.mutable_value();
  }

 private:
  size_t num_fields() const override { return 2; }
  const Field* field(int i) const override {
    return std::array<const Field*, 2>{&version_, &params_}[i];
  }
  Uint32Field version_{1};
  MessageField<KmsEnvelopeAeadKeyFormatTP> params_{2};
};

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

absl::StatusOr<LegacyKmsEnvelopeAeadParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kRaw:
      return LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return LegacyKmsEnvelopeAeadParameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine LegacyKmsEnvelopeAeadParameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    LegacyKmsEnvelopeAeadParameters::Variant variant) {
  switch (variant) {
    case LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case LegacyKmsEnvelopeAeadParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

absl::StatusOr<std::unique_ptr<Parameters>> ParametersFromKeyTemplate(
    const KeyTemplateTP& key_template) {
  absl::StatusOr<ProtoParametersSerialization> proto_params_serialization =
      ProtoParametersSerialization::Create(key_template);
  if (!proto_params_serialization.ok()) {
    return proto_params_serialization.status();
  }
  return GlobalSerializationRegistry().ParseParameters(
      *proto_params_serialization);
}

absl::StatusOr<KeyTemplateTP> ParametersToKeyTemplate(
    const Parameters& parameters) {
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      GlobalSerializationRegistry()
          .SerializeParameters<ProtoParametersSerialization>(parameters);
  if (!serialization.ok()) {
    return serialization.status();
  }
  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  if (proto_serialization == nullptr) {
    return absl::InternalError("Failed to serialize proto parameters.");
  }
  return proto_serialization->GetKeyTemplate();
}

absl::StatusOr<LegacyKmsEnvelopeAeadParameters> GetParametersFromKeyFormat(
    const KmsEnvelopeAeadKeyFormatTP& proto_key_format,
    OutputPrefixTypeEnum output_prefix_type) {
  absl::StatusOr<LegacyKmsEnvelopeAeadParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  KeyTemplateTP raw_dek_template = proto_key_format.dek_template();
  raw_dek_template.set_output_prefix_type(OutputPrefixTypeEnum::kRaw);

  absl::StatusOr<std::unique_ptr<Parameters>> dek_parameters =
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

absl::StatusOr<LegacyKmsEnvelopeAeadParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing LegacyKmsEnvelopeAeadParameters.");
  }

  KmsEnvelopeAeadKeyFormatTP proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError(
        "Failed to parse KmsEnvelopeAeadKeyFormat proto");
  }

  return GetParametersFromKeyFormat(proto_key_format,
                                    key_template.output_prefix_type());
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const LegacyKmsEnvelopeAeadParameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<KeyTemplateTP> dek_key_template =
      ParametersToKeyTemplate(parameters.GetDekParameters());
  if (!dek_key_template.ok()) {
    return dek_key_template.status();
  }

  KmsEnvelopeAeadKeyFormatTP proto_key_format;
  proto_key_format.set_kek_uri(parameters.GetKeyUri());
  proto_key_format.mutable_dek_template()->set_output_prefix_type(
      dek_key_template->output_prefix_type());
  proto_key_format.mutable_dek_template()->set_value(dek_key_template->value());
  proto_key_format.mutable_dek_template()->set_type_url(
      dek_key_template->type_url());

  return ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

absl::StatusOr<LegacyKmsEnvelopeAeadKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing LegacyKmsEnvelopeAeadKey.");
  }
  KmsEnvelopeAeadKeyTP key;
  if (!key.ParseFromString(serialization.SerializedKeyProto().GetSecret(
          GetInsecureSecretKeyAccessInternal()))) {
    return absl::InvalidArgumentError(
        "Failed to parse KmsEnvelopeAeadKey proto");
  }
  if (key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      GetParametersFromKeyFormat(key.params(),
                                 serialization.GetOutputPrefixTypeEnum());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return LegacyKmsEnvelopeAeadKey::Create(*parameters,
                                          serialization.IdRequirement());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const LegacyKmsEnvelopeAeadKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<KeyTemplateTP> dek_key_template =
      ParametersToKeyTemplate(key.GetParameters().GetDekParameters());
  if (!dek_key_template.ok()) {
    return dek_key_template.status();
  }

  KmsEnvelopeAeadKeyTP key_proto;
  key_proto.set_version(0);
  key_proto.mutable_params()->set_kek_uri(key.GetParameters().GetKeyUri());
  key_proto.mutable_params()->mutable_dek_template()->set_output_prefix_type(
      dek_key_template->output_prefix_type());
  key_proto.mutable_params()->mutable_dek_template()->set_value(
      dek_key_template->value());
  key_proto.mutable_params()->mutable_dek_template()->set_type_url(
      dek_key_template->type_url());

  SecretData serialized_key = key_proto.SerializeAsSecretData();

  RestrictedData restricted_output = RestrictedData(
      std::move(serialized_key), GetInsecureSecretKeyAccessInternal());

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, KeyMaterialTypeEnum::kRemote,
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

absl::Status RegisterLegacyKmsEnvelopeAeadProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status = registry.RegisterParametersParser(
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

absl::Status RegisterLegacyKmsEnvelopeAeadProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status = builder.RegisterParametersParser(
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
