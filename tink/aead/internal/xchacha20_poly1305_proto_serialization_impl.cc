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

#include "tink/aead/internal/xchacha20_poly1305_proto_serialization_impl.h"

#include <array>
#include <cstdint>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/internal/xchacha20_poly1305_proto_format.h"
#include "tink/aead/xchacha20_poly1305_key.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
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
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::OwningField;
using ::crypto::tink::internal::proto_parsing::SecretDataOwningField;
using ::crypto::tink::internal::proto_parsing::Uint32OwningField;

class ProtoXChaCha20Poly1305Key : public Message<ProtoXChaCha20Poly1305Key> {
 public:
  ProtoXChaCha20Poly1305Key() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(absl::string_view value) {
    *key_value_.mutable_value() = util::SecretDataFromStringView(value);
  }

  std::array<const OwningField*, 2> GetFields() const {
    return {&version_, &key_value_};
  }

 private:
  Uint32OwningField version_{1};
  SecretDataOwningField key_value_{3};
};

using XChaCha20Poly1305ProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   XChaCha20Poly1305Parameters>;
using XChaCha20Poly1305ProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<XChaCha20Poly1305Parameters,
                                       internal::ProtoParametersSerialization>;
using XChaCha20Poly1305ProtoKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization,
                            XChaCha20Poly1305Key>;
using XChaCha20Poly1305ProtoKeySerializerImpl =
    internal::KeySerializerImpl<XChaCha20Poly1305Key,
                                internal::ProtoKeySerialization>;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";

absl::StatusOr<XChaCha20Poly1305Parameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixTypeEnum::kCrunchy:
      return XChaCha20Poly1305Parameters::Variant::kCrunchy;
    case OutputPrefixTypeEnum::kRaw:
      return XChaCha20Poly1305Parameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return XChaCha20Poly1305Parameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine XChaCha20Poly1305Parameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    XChaCha20Poly1305Parameters::Variant variant) {
  switch (variant) {
    case XChaCha20Poly1305Parameters::Variant::kCrunchy:
      return OutputPrefixTypeEnum::kCrunchy;
    case XChaCha20Poly1305Parameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case XChaCha20Poly1305Parameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

absl::StatusOr<XChaCha20Poly1305Parameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  const ProtoKeyTemplate& template_struct = serialization.GetProtoKeyTemplate();
  if (template_struct.type_url() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing XChaCha20Poly1305Parameters.");
  }
  ProtoXChaCha20Poly1305KeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(template_struct.value())) {
    return absl::InvalidArgumentError(
        "Failed to parse XChaCha20Poly1305KeyFormat proto");
  }
  if (proto_key_format.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<XChaCha20Poly1305Parameters::Variant> variant =
      ToVariant(template_struct.output_prefix_type());
  if (!variant.ok()) return variant.status();

  return XChaCha20Poly1305Parameters::Create(*variant);
}

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const XChaCha20Poly1305Parameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) return output_prefix_type.status();

  ProtoXChaCha20Poly1305KeyFormat proto_key_format;
  proto_key_format.set_version(0);
  return internal::ProtoParametersSerialization::Create(
      kTypeUrl, *output_prefix_type, proto_key_format.SerializeAsString());
}

absl::StatusOr<XChaCha20Poly1305Key> ParseKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing XChaCha20Poly1305Key.");
  }
  if (!token.has_value()) {
    return absl::InvalidArgumentError("SecretKeyAccess is required");
  }

  ProtoXChaCha20Poly1305Key key;
  if (!key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError(
        "Failed to parse XChaCha20Poly1305Key proto");
  }
  if (key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<XChaCha20Poly1305Parameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixTypeEnum());
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<XChaCha20Poly1305Parameters> parameters =
      XChaCha20Poly1305Parameters::Create(*variant);
  if (!parameters.ok()) return parameters.status();

  return XChaCha20Poly1305Key::Create(
      parameters->GetVariant(), RestrictedData(key.key_value(), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializeKey(
    const XChaCha20Poly1305Key& key,
    absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetKeyBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) return restricted_input.status();
  if (!token.has_value()) {
    return absl::InvalidArgumentError("SecretKeyAccess is required");
  }

  ProtoXChaCha20Poly1305Key proto_key;
  proto_key.set_version(0);
  proto_key.set_key_value(restricted_input->GetSecret(*token));
  SecretData serialized_key = proto_key.SerializeAsSecretData();
  RestrictedData restricted_output =
      RestrictedData(std::move(serialized_key), *token);

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return internal::ProtoKeySerialization::Create(
      kTypeUrl, restricted_output, KeyMaterialTypeEnum::kSymmetric,
      *output_prefix_type, key.GetIdRequirement());
}

XChaCha20Poly1305ProtoParametersParserImpl*
XChaCha20Poly1305ProtoParametersParser() {
  static auto* parser =
      new XChaCha20Poly1305ProtoParametersParserImpl(kTypeUrl, ParseParameters);
  return parser;
}

XChaCha20Poly1305ProtoParametersSerializerImpl*
XChaCha20Poly1305ProtoParametersSerializer() {
  static auto* serializer = new XChaCha20Poly1305ProtoParametersSerializerImpl(
      kTypeUrl, SerializeParameters);
  return serializer;
}

XChaCha20Poly1305ProtoKeyParserImpl* XChaCha20Poly1305ProtoKeyParser() {
  static auto* parser =
      new XChaCha20Poly1305ProtoKeyParserImpl(kTypeUrl, ParseKey);
  return parser;
}

XChaCha20Poly1305ProtoKeySerializerImpl* XChaCha20Poly1305ProtoKeySerializer() {
  static auto* serializer =
      new XChaCha20Poly1305ProtoKeySerializerImpl(SerializeKey);
  return serializer;
}

}  // namespace

absl::Status RegisterXChaCha20Poly1305ProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status = registry.RegisterParametersParser(
      XChaCha20Poly1305ProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterParametersSerializer(
      XChaCha20Poly1305ProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(XChaCha20Poly1305ProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(XChaCha20Poly1305ProtoKeySerializer());
}

absl::Status RegisterXChaCha20Poly1305ProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status = builder.RegisterParametersParser(
      XChaCha20Poly1305ProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterParametersSerializer(
      XChaCha20Poly1305ProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(XChaCha20Poly1305ProtoKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(XChaCha20Poly1305ProtoKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
