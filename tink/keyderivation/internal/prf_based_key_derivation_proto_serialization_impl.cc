// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/keyderivation/internal/prf_based_key_derivation_proto_serialization_impl.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/internal/aes_ctr_hmac_aead_proto_serialization_impl.h"
#include "tink/aead/internal/aes_gcm_proto_serialization_impl.h"
#include "tink/aead/internal/aes_gcm_siv_proto_serialization_impl.h"
#include "tink/aead/internal/xchacha20_poly1305_proto_serialization_impl.h"
#include "tink/daead/internal/aes_siv_proto_serialization_impl.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/keyderivation/prf_based_key_derivation_key.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"
#include "tink/mac/internal/hmac_proto_serialization_impl.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/prf/internal/aes_cmac_prf_proto_serialization_impl.h"
#include "tink/prf/internal/hkdf_prf_proto_serialization_impl.h"
#include "tink/prf/internal/hmac_prf_proto_serialization_impl.h"
#include "tink/prf/prf_key.h"
#include "tink/prf/prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/internal/ecdsa_proto_serialization_impl.h"
#include "tink/signature/internal/ed25519_proto_serialization_impl.h"
#include "tink/signature/internal/ml_dsa_proto_serialization_impl.h"
#include "tink/signature/internal/slh_dsa_proto_serialization_impl.h"
#include "tink/streamingaead/internal/aes_ctr_hmac_streaming_proto_serialization_impl.h"
#include "tink/streamingaead/internal/aes_gcm_hkdf_streaming_proto_serialization_impl.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::KeyDataTP;
using ::crypto::tink::internal::KeyTemplateTP;
using ::crypto::tink::internal::proto_parsing::Field;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageField;
using ::crypto::tink::internal::proto_parsing::Uint32Field;

class PrfBasedDeriverParamsTP : public Message {
 public:
  PrfBasedDeriverParamsTP() = default;
  using Message::SerializeAsString;

  const KeyTemplateTP& derived_key_template() const {
    return derived_key_template_.value();
  }
  KeyTemplateTP* mutable_derived_key_template() {
    return derived_key_template_.mutable_value();
  }

 private:
  size_t num_fields() const override { return 1; }
  const Field* field(int i) const override {
    return std::array<const Field*, 1>{&derived_key_template_}[i];
  }

  MessageField<KeyTemplateTP> derived_key_template_{1};
};

class PrfBasedDeriverKeyFormatTP : public Message {
 public:
  PrfBasedDeriverKeyFormatTP() = default;
  using Message::SerializeAsString;

  const KeyTemplateTP& prf_key_template() const {
    return prf_key_template_.value();
  }
  KeyTemplateTP* mutable_prf_key_template() {
    return prf_key_template_.mutable_value();
  }

  const PrfBasedDeriverParamsTP& params() const { return params_.value(); }
  PrfBasedDeriverParamsTP* mutable_params() { return params_.mutable_value(); }

 private:
  size_t num_fields() const override { return 2; }
  const Field* field(int i) const override {
    return std::array<const Field*, 2>{&prf_key_template_, &params_}[i];
  }

  MessageField<KeyTemplateTP> prf_key_template_{1};
  MessageField<PrfBasedDeriverParamsTP> params_{2};
};

class PrfBasedDeriverKeyTP : public Message {
 public:
  PrfBasedDeriverKeyTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const KeyDataTP& prf_key() const { return prf_key_.value(); }
  KeyDataTP* mutable_prf_key() { return prf_key_.mutable_value(); }

  const PrfBasedDeriverParamsTP& params() const { return params_.value(); }
  PrfBasedDeriverParamsTP* mutable_params() { return params_.mutable_value(); }

 private:
  size_t num_fields() const override { return 3; }
  const Field* field(int i) const override {
    return std::array<const Field*, 3>{&version_, &prf_key_, &params_}[i];
  }

  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  MessageField<KeyDataTP> prf_key_{2};
  MessageField<PrfBasedDeriverParamsTP> params_{3};
};

using PrfBasedKeyDerivationProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization,
                         PrfBasedKeyDerivationParameters>;
using PrfBasedKeyDerivationProtoParametersSerializerImpl =
    ParametersSerializerImpl<PrfBasedKeyDerivationParameters,
                             ProtoParametersSerialization>;
using PrfBasedKeyDerivationProtoKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, PrfBasedKeyDerivationKey>;
using PrfBasedKeyDerivationProtoKeySerializerImpl =
    KeySerializerImpl<PrfBasedKeyDerivationKey, ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey";

const SerializationRegistry& GetPrfSerializationRegistry() {
  static const absl::NoDestructor<SerializationRegistry> kRegistry([] {
    SerializationRegistry registry;
    // PrfBasedDeriver::New() (via ConfigPrfForDeriver()) only supports HkdfPrf.
    ABSL_CHECK_OK(RegisterHkdfPrfProtoSerializationWithRegistry(registry));
    return registry;
  }());
  return *kRegistry;
}

const SerializationRegistry& GetDerivedKeySerializationRegistry() {
  static const absl::NoDestructor<SerializationRegistry> kRegistry([] {
    SerializationRegistry registry;

    // AEAD
    ABSL_CHECK_OK(
        RegisterAesCtrHmacAeadProtoSerializationWithRegistry(registry));
    ABSL_CHECK_OK(RegisterAesGcmProtoSerializationWithRegistry(registry));
    // Included for cross-language compatibility with Tink Java, which supports
    // deriving AES-GCM-SIV keys. It might be better to remove this.
    ABSL_CHECK_OK(RegisterAesGcmSivProtoSerializationWithRegistry(registry));
    ABSL_CHECK_OK(
        RegisterXChaCha20Poly1305ProtoSerializationWithRegistry(registry));

    // Deterministic AEAD
    ABSL_CHECK_OK(RegisterAesSivProtoSerializationWithRegistry(registry));

    // MAC
    ABSL_CHECK_OK(RegisterHmacProtoSerializationWithRegistry(registry));

    // PRF
    ABSL_CHECK_OK(RegisterAesCmacPrfProtoSerializationWithRegistry(registry));
    ABSL_CHECK_OK(RegisterHkdfPrfProtoSerializationWithRegistry(registry));
    ABSL_CHECK_OK(RegisterHmacPrfProtoSerializationWithRegistry(registry));

    // Signature
    ABSL_CHECK_OK(RegisterEcdsaProtoSerializationWithRegistry(registry));
    ABSL_CHECK_OK(RegisterEd25519ProtoSerializationWithRegistry(registry));
    ABSL_CHECK_OK(RegisterMlDsaProtoSerializationWithRegistry(registry));
    ABSL_CHECK_OK(RegisterSlhDsaProtoSerializationWithRegistry(registry));

    // Streaming AEAD
    ABSL_CHECK_OK(
        RegisterAesCtrHmacStreamingProtoSerializationWithRegistry(registry));
    ABSL_CHECK_OK(
        RegisterAesGcmHkdfStreamingProtoSerializationWithRegistry(registry));

    return registry;
  }());
  return *kRegistry;
}

absl::StatusOr<std::unique_ptr<Parameters>> DerivedKeyParametersFromKeyTemplate(
    const KeyTemplateTP& key_template) {
  absl::StatusOr<ProtoParametersSerialization> proto_params_serialization =
      ProtoParametersSerialization::Create(key_template);
  if (!proto_params_serialization.ok()) {
    return proto_params_serialization.status();
  }
  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      GetDerivedKeySerializationRegistry().ParseParameters(
          *proto_params_serialization);
  if (absl::IsNotFound(parameters.status())) {
    return absl::InvalidArgumentError(
        "Unsupported derived key parameters when parsing "
        "PrfBasedKeyDerivationParameters.");
  }
  return parameters;
}

absl::StatusOr<std::unique_ptr<const PrfParameters>>
PrfParametersFromKeyTemplate(const KeyTemplateTP& key_template) {
  absl::StatusOr<ProtoParametersSerialization> proto_params_serialization =
      ProtoParametersSerialization::Create(key_template);
  if (!proto_params_serialization.ok()) {
    return proto_params_serialization.status();
  }
  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      GetPrfSerializationRegistry().ParseParameters(
          *proto_params_serialization);
  if (absl::IsNotFound(parameters.status())) {
    return absl::InvalidArgumentError(
        "Unsupported PRF parameters when parsing "
        "PrfBasedKeyDerivationParameters.");
  }
  if (!parameters.ok()) {
    return parameters.status();
  }
  const PrfParameters* prf_parameters =
      dynamic_cast<const PrfParameters*>(parameters->get());
  if (prf_parameters == nullptr) {
    return absl::InvalidArgumentError(
        "Non-PRF parameters stored in the `prf_key_template` field.");
  }
  return absl::WrapUnique(
      dynamic_cast<const PrfParameters*>(parameters->release()));
}

absl::StatusOr<KeyTemplateTP> ParametersToKeyTemplate(
    const Parameters& parameters, const SerializationRegistry& registry) {
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(parameters);
  if (!serialization.ok()) {
    return serialization.status();
  }

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  if (proto_serialization == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Failed to serialize proto parameters.");
  }

  return proto_serialization->GetKeyTemplate();
}

absl::StatusOr<std::unique_ptr<const PrfKey>> PrfKeyFromKeyData(
    const KeyDataTP& key_data, SecretKeyAccessToken token) {
  absl::StatusOr<ProtoKeySerialization> proto_key_serialization =
      ProtoKeySerialization::Create(
          key_data.type_url(), RestrictedData(key_data.value(), token),
          key_data.key_material_type(),
          google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
          /*id_requirement=*/std::nullopt);
  if (!proto_key_serialization.ok()) {
    return proto_key_serialization.status();
  }

  absl::StatusOr<std::unique_ptr<Key>> key =
      GetPrfSerializationRegistry().ParseKey(*proto_key_serialization, token);
  if (absl::IsNotFound(key.status())) {
    return absl::InvalidArgumentError(
        "Unsupported PRF key when parsing PrfBasedKeyDerivationKey.");
  }
  if (!key.ok()) {
    return key.status();
  }

  const PrfKey* prf_key = dynamic_cast<const PrfKey*>(key->get());
  if (prf_key == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Non-PRF key stored in the `prf_key` field.");
  }

  return absl::WrapUnique(dynamic_cast<const PrfKey*>(key->release()));
}

absl::StatusOr<KeyDataTP> PrfKeyToKeyData(const PrfKey& prf_key,
                                          SecretKeyAccessToken token) {
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      GetPrfSerializationRegistry().SerializeKey<ProtoKeySerialization>(prf_key,
                                                                        token);
  if (!serialization.ok()) {
    return serialization.status();
  }

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  if (proto_serialization == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Failed to serialize proto key.");
  }

  KeyDataTP key_data;
  key_data.set_value(proto_serialization->SerializedKeyProto().Get(token));
  key_data.set_type_url(proto_serialization->TypeUrl());
  key_data.set_key_material_type(proto_serialization->GetKeyMaterialTypeTP());

  return key_data;
}

absl::StatusOr<PrfBasedKeyDerivationParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kTypeUrl) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing PrfBasedKeyDerivationParameters.");
  }

  PrfBasedDeriverKeyFormatTP proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse PrfBasedDeriverKeyFormatTP.");
  }

  if (key_template.output_prefix_type() !=
      proto_key_format.params().derived_key_template().output_prefix_type()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsed output prefix type must match derived key output prefix type.");
  }

  absl::StatusOr<std::unique_ptr<Parameters>> derived_key_parameters =
      DerivedKeyParametersFromKeyTemplate(
          proto_key_format.params().derived_key_template());
  if (!derived_key_parameters.ok()) {
    return derived_key_parameters.status();
  }

  absl::StatusOr<std::unique_ptr<const PrfParameters>> prf_parameters =
      PrfParametersFromKeyTemplate(proto_key_format.prf_key_template());
  if (!prf_parameters.ok()) {
    return prf_parameters.status();
  }

  return PrfBasedKeyDerivationParameters::Builder()
      .SetPrfParameters(**prf_parameters)
      .SetDerivedKeyParameters(**derived_key_parameters)
      .Build();
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const PrfBasedKeyDerivationParameters& parameters) {
  absl::StatusOr<KeyTemplateTP> prf_key_template = ParametersToKeyTemplate(
      parameters.GetPrfParameters(), GetPrfSerializationRegistry());
  if (!prf_key_template.ok()) {
    return prf_key_template.status();
  }

  absl::StatusOr<KeyTemplateTP> derived_key_template =
      ParametersToKeyTemplate(parameters.GetDerivedKeyParameters(),
                              GetDerivedKeySerializationRegistry());
  if (!derived_key_template.ok()) {
    return derived_key_template.status();
  }

  PrfBasedDeriverKeyFormatTP proto_key_format;
  *proto_key_format.mutable_prf_key_template() = *prf_key_template;
  *proto_key_format.mutable_params()->mutable_derived_key_template() =
      *derived_key_template;

  return ProtoParametersSerialization::Create(
      kTypeUrl, derived_key_template->output_prefix_type(),
      proto_key_format.SerializeAsString());
}

absl::StatusOr<PrfBasedKeyDerivationKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Wrong type URL when parsing PrfBasedKeyDerivationKey.");
  }
  if (!token.has_value()) {
    return absl::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required.");
  }

  PrfBasedDeriverKeyTP proto_key;
  if (!proto_key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse PrfBasedDeriverKeyTP.");
  }

  if (proto_key.version() != 0) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Only version 0 keys are accepted.");
  }

  if (serialization.GetOutputPrefixTypeTP() !=
      proto_key.params().derived_key_template().output_prefix_type()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Parsed output prefix type must match derived key output prefix type.");
  }

  absl::StatusOr<std::unique_ptr<Parameters>> derived_key_parameters =
      DerivedKeyParametersFromKeyTemplate(
          proto_key.params().derived_key_template());
  if (!derived_key_parameters.ok()) {
    return derived_key_parameters.status();
  }

  absl::StatusOr<std::unique_ptr<const PrfKey>> prf_key =
      PrfKeyFromKeyData(proto_key.prf_key(), *token);
  if (!prf_key.ok()) {
    return prf_key.status();
  }

  ABSL_ASSIGN_OR_RETURN(PrfBasedKeyDerivationParameters parameters,
                        PrfBasedKeyDerivationParameters::Builder()
                            .SetPrfParameters((*prf_key)->GetParameters())
                            .SetDerivedKeyParameters(**derived_key_parameters)
                            .Build());
  return PrfBasedKeyDerivationKey::Create(parameters, **prf_key,
                                          serialization.IdRequirement(),
                                          GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const PrfBasedKeyDerivationKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::Status(absl::StatusCode::kPermissionDenied,
                        "SecretKeyAccess is required.");
  }

  absl::StatusOr<KeyTemplateTP> derived_key_template =
      ParametersToKeyTemplate(key.GetParameters().GetDerivedKeyParameters(),
                              GetDerivedKeySerializationRegistry());
  if (!derived_key_template.ok()) {
    return derived_key_template.status();
  }

  PrfBasedDeriverKeyTP proto_key;
  proto_key.set_version(0);
  absl::StatusOr<KeyDataTP> prf_key_data =
      PrfKeyToKeyData(key.GetPrfKey(), *token);
  if (!prf_key_data.ok()) {
    return prf_key_data.status();
  }
  *proto_key.mutable_prf_key() = *prf_key_data;
  *proto_key.mutable_params()->mutable_derived_key_template() =
      *derived_key_template;

  return ProtoKeySerialization::Create(
      kTypeUrl, RestrictedData(proto_key.SerializeAsSecretData(), *token),
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::kSymmetric,
      derived_key_template->output_prefix_type(), key.GetIdRequirement());
}

PrfBasedKeyDerivationProtoParametersParserImpl*
PrfBasedKeyDerivationProtoParametersParser() {
  static auto* parser = new PrfBasedKeyDerivationProtoParametersParserImpl(
      kTypeUrl, ParseParameters);
  return parser;
}

PrfBasedKeyDerivationProtoParametersSerializerImpl*
PrfBasedKeyDerivationProtoParametersSerializer() {
  static auto* serializer =
      new PrfBasedKeyDerivationProtoParametersSerializerImpl(
          kTypeUrl, SerializeParameters);
  return serializer;
}

PrfBasedKeyDerivationProtoKeyParserImpl* PrfBasedKeyDerivationProtoKeyParser() {
  static auto* parser =
      new PrfBasedKeyDerivationProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

PrfBasedKeyDerivationProtoKeySerializerImpl*
PrfBasedKeyDerivationProtoKeySerializer() {
  static auto* serializer =
      new PrfBasedKeyDerivationProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status = registry.RegisterParametersParser(
      PrfBasedKeyDerivationProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      PrfBasedKeyDerivationProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(PrfBasedKeyDerivationProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(
      PrfBasedKeyDerivationProtoKeySerializer());
}

absl::Status RegisterPrfBasedKeyDerivationProtoSerializationWithRegistry(
    SerializationRegistry& registry) {
  absl::Status status = registry.RegisterParametersParser(
      PrfBasedKeyDerivationProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      PrfBasedKeyDerivationProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(PrfBasedKeyDerivationProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(
      PrfBasedKeyDerivationProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
