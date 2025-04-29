// Copyright 2025 Google LLC
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

#include "tink/experimental/pqcrypto/kem/internal/cecpq2_proto_serialization_impl.h"

#include <cstdint>
#include <memory>
#include <string>

#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_parameters.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_private_key.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/common_proto_enums.h"
#include "tink/internal/global_serialization_registry.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/proto_parser.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using Cecpq2ProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, Cecpq2Parameters>;
using Cecpq2ProtoParametersSerializerImpl =
    ParametersSerializerImpl<Cecpq2Parameters, ProtoParametersSerialization>;
using Cecpq2ProtoPublicKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, Cecpq2PublicKey>;
using Cecpq2ProtoPublicKeySerializerImpl =
    KeySerializerImpl<Cecpq2PublicKey, ProtoKeySerialization>;
using Cecpq2ProtoPrivateKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, Cecpq2PrivateKey>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.Cecpq2AeadHkdfPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.Cecpq2AeadHkdfPublicKey";

absl::StatusOr<Cecpq2Parameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kRaw:
      return Cecpq2Parameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return Cecpq2Parameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine Cecpq2Parameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    Cecpq2Parameters::Variant variant) {
  switch (variant) {
    case Cecpq2Parameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case Cecpq2Parameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

absl::StatusOr<std::unique_ptr<Parameters>> DemParametersFromKeyTemplate(
    const KeyTemplateStruct& key_template) {
  absl::StatusOr<ProtoParametersSerialization> proto_params_serialization =
      ProtoParametersSerialization::Create(key_template);
  if (!proto_params_serialization.ok()) {
    return proto_params_serialization.status();
  }
  return GlobalSerializationRegistry().ParseParameters(
      *proto_params_serialization);
}

absl::StatusOr<KeyTemplateStruct> DemParametersToKeyTemplate(
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

  return proto_serialization->GetKeyTemplateStruct();
}

struct Cecpq2HkdfKemParamsStruct {
  EllipticCurveTypeEnum curve_type;
  EcPointFormatEnum ec_point_format;
  HashTypeEnum hkdf_hash_type;
  std::string hkdf_salt;

  static ProtoParser<Cecpq2HkdfKemParamsStruct> CreateParser() {
    return ProtoParserBuilder<Cecpq2HkdfKemParamsStruct>()
        .AddEnumField(1, &Cecpq2HkdfKemParamsStruct::curve_type,
                      &EllipticCurveTypeEnumIsValid)
        .AddEnumField(2, &Cecpq2HkdfKemParamsStruct::ec_point_format,
                      &EcPointFormatEnumIsValid)
        .AddEnumField(3, &Cecpq2HkdfKemParamsStruct::hkdf_hash_type,
                      &HashTypeEnumIsValid)
        .AddBytesStringField(11, &Cecpq2HkdfKemParamsStruct::hkdf_salt)
        .BuildOrDie();
  }
};

struct Cecpq2AeadDemParamsStruct {
  KeyTemplateStruct aead_dem;

  static ProtoParser<Cecpq2AeadDemParamsStruct> CreateParser() {
    return ProtoParserBuilder<Cecpq2AeadDemParamsStruct>()
        .AddMessageField(2, &Cecpq2AeadDemParamsStruct::aead_dem,
                         KeyTemplateStruct::CreateParser())
        .BuildOrDie();
  }
};

struct Cecpq2AeadHkdfParamsStruct {
  Cecpq2HkdfKemParamsStruct kem_params;
  Cecpq2AeadDemParamsStruct dem_params;

  static ProtoParser<Cecpq2AeadHkdfParamsStruct> CreateParser() {
    return ProtoParserBuilder<Cecpq2AeadHkdfParamsStruct>()
        .AddMessageField(1, &Cecpq2AeadHkdfParamsStruct::kem_params,
                         Cecpq2HkdfKemParamsStruct::CreateParser())
        .AddMessageField(2, &Cecpq2AeadHkdfParamsStruct::dem_params,
                         Cecpq2AeadDemParamsStruct::CreateParser())
        .BuildOrDie();
  }
};

struct Cecpq2AeadHkdfKeyFormatStruct {
  Cecpq2AeadHkdfParamsStruct params;

  static ProtoParser<Cecpq2AeadHkdfKeyFormatStruct> CreateParser() {
    return ProtoParserBuilder<Cecpq2AeadHkdfKeyFormatStruct>()
        .AddMessageField(1, &Cecpq2AeadHkdfKeyFormatStruct::params,
                         Cecpq2AeadHkdfParamsStruct::CreateParser())
        .BuildOrDie();
  }

  static const ProtoParser<Cecpq2AeadHkdfKeyFormatStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<Cecpq2AeadHkdfKeyFormatStruct>>
        parser{CreateParser()};
    return *parser;
  }
};

struct Cecpq2AeadHkdfPublicKeyStruct {
  uint32_t version;
  Cecpq2AeadHkdfParamsStruct params;
  std::string x25519_public_key_x;
  std::string x25519_public_key_y;
  std::string hrss_public_key_marshalled;

  static ProtoParser<Cecpq2AeadHkdfPublicKeyStruct> CreateParser() {
    return ProtoParserBuilder<Cecpq2AeadHkdfPublicKeyStruct>()
        .AddUint32Field(1, &Cecpq2AeadHkdfPublicKeyStruct::version)
        .AddMessageField(2, &Cecpq2AeadHkdfPublicKeyStruct::params,
                         Cecpq2AeadHkdfParamsStruct::CreateParser())
        .AddBytesStringField(
            3, &Cecpq2AeadHkdfPublicKeyStruct::x25519_public_key_x)
        .AddBytesStringField(
            4, &Cecpq2AeadHkdfPublicKeyStruct::x25519_public_key_y)
        .AddBytesStringField(
            5, &Cecpq2AeadHkdfPublicKeyStruct::hrss_public_key_marshalled)
        .BuildOrDie();
  }

  static const ProtoParser<Cecpq2AeadHkdfPublicKeyStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<Cecpq2AeadHkdfPublicKeyStruct>>
        parser{CreateParser()};
    return *parser;
  }
};

struct Cecpq2AeadHkdfPrivateKeyStruct {
  uint32_t version;
  Cecpq2AeadHkdfPublicKeyStruct public_key;
  SecretData x25519_private_key;
  SecretData hrss_private_key_seed;

  static ProtoParser<Cecpq2AeadHkdfPrivateKeyStruct> CreateParser() {
    return ProtoParserBuilder<Cecpq2AeadHkdfPrivateKeyStruct>()
        .AddUint32Field(1, &Cecpq2AeadHkdfPrivateKeyStruct::version)
        .AddMessageField(2, &Cecpq2AeadHkdfPrivateKeyStruct::public_key,
                         Cecpq2AeadHkdfPublicKeyStruct::CreateParser())
        .AddBytesSecretDataField(
            3, &Cecpq2AeadHkdfPrivateKeyStruct::x25519_private_key)
        .AddBytesSecretDataField(
            4, &Cecpq2AeadHkdfPrivateKeyStruct::hrss_private_key_seed)
        .BuildOrDie();
  }

  static const ProtoParser<Cecpq2AeadHkdfPrivateKeyStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<Cecpq2AeadHkdfPrivateKeyStruct>>
        parser{CreateParser()};
    return *parser;
  }
};

absl::StatusOr<Cecpq2Parameters> ToParameters(
    Cecpq2AeadHkdfParamsStruct& params,
    OutputPrefixTypeEnum output_prefix_type) {
  // Ignore legacy DEM key templates that set a non-RAW prefix.
  params.dem_params.aead_dem.output_prefix_type = OutputPrefixTypeEnum::kRaw;

  absl::StatusOr<std::unique_ptr<Parameters>> dem_parameters =
      DemParametersFromKeyTemplate(params.dem_params.aead_dem);
  if (!dem_parameters.ok()) {
    return dem_parameters.status();
  }

  absl::StatusOr<Cecpq2Parameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::optional<std::string> salt = absl::nullopt;
  if (!params.kem_params.hkdf_salt.empty()) {
    salt = params.kem_params.hkdf_salt;
  }

  return Cecpq2Parameters::Create(**dem_parameters, salt, *variant);
}

absl::StatusOr<Cecpq2AeadHkdfParamsStruct> FromParameters(
    const Cecpq2Parameters& parameters) {
  absl::StatusOr<KeyTemplateStruct> dem_key_template =
      DemParametersToKeyTemplate(parameters.GetDemParameters());
  if (!dem_key_template.ok()) {
    return dem_key_template.status();
  }

  Cecpq2AeadHkdfParamsStruct params;
  params.kem_params.curve_type = EllipticCurveTypeEnum::kCurve25519;
  params.kem_params.ec_point_format = EcPointFormatEnum::kCompressed;
  params.kem_params.hkdf_hash_type = HashTypeEnum::kSha256;
  if (parameters.GetSalt().has_value()) {
    params.kem_params.hkdf_salt = *parameters.GetSalt();
  }
  params.dem_params.aead_dem = *dem_key_template;

  return params;
}

absl::StatusOr<Cecpq2PublicKey> ToPublicKey(
    const Cecpq2Parameters& parameters,
    const Cecpq2AeadHkdfPublicKeyStruct& proto_key,
    absl::optional<int> id_requirement) {
  if (!proto_key.x25519_public_key_y.empty()) {
    return absl::InvalidArgumentError(
        "Cecpq2AeadHkdfPublicKey.x25519_public_key_y must be empty.");
  }

  Cecpq2PublicKey::Builder builder =
      Cecpq2PublicKey::Builder()
          .SetParameters(parameters)
          .SetX25519PublicKeyBytes(proto_key.x25519_public_key_x)
          .SetHrssPublicKeyBytes(proto_key.hrss_public_key_marshalled);
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(*id_requirement);
  }
  return builder.Build(GetPartialKeyAccess());
}

absl::StatusOr<Cecpq2AeadHkdfPublicKeyStruct> FromPublicKey(
    const Cecpq2AeadHkdfParamsStruct& proto_params,
    const Cecpq2PublicKey& public_key) {
  Cecpq2AeadHkdfPublicKeyStruct proto_public_key;
  proto_public_key.version = 0;
  proto_public_key.params = proto_params;
  proto_public_key.x25519_public_key_x =
      public_key.GetX25519PublicKeyBytes(GetPartialKeyAccess());
  proto_public_key.hrss_public_key_marshalled =
      public_key.GetHrssPublicKeyBytes(GetPartialKeyAccess());

  return proto_public_key;
}

absl::StatusOr<Cecpq2PrivateKey> ToPrivateKey(
    const Cecpq2PublicKey& public_key,
    const Cecpq2AeadHkdfPrivateKeyStruct& proto_private_key) {
  return Cecpq2PrivateKey::Builder()
      .SetPublicKey(public_key)
      .SetX25519PrivateKeyBytes(RestrictedData(
          proto_private_key.x25519_private_key, InsecureSecretKeyAccess::Get()))
      .SetHrssPrivateKeySeed(
          RestrictedData(proto_private_key.hrss_private_key_seed,
                         InsecureSecretKeyAccess::Get()))
      .Build(GetPartialKeyAccess());
}

absl::StatusOr<Cecpq2Parameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplateStruct().type_url != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing Cecpq2Parameters.");
  }

  absl::StatusOr<Cecpq2AeadHkdfKeyFormatStruct> proto_key_format =
      Cecpq2AeadHkdfKeyFormatStruct::GetParser().Parse(
          serialization.GetKeyTemplateStruct().value);
  if (!proto_key_format.ok()) {
    return proto_key_format.status();
  }

  return ToParameters(proto_key_format->params,
                      serialization.GetKeyTemplateStruct().output_prefix_type);
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const Cecpq2Parameters& parameters) {
  absl::StatusOr<Cecpq2AeadHkdfParamsStruct> proto_params =
      FromParameters(parameters);
  if (!proto_params.ok()) {
    return proto_params.status();
  }

  Cecpq2AeadHkdfKeyFormatStruct proto_key_format;
  proto_key_format.params = *proto_params;

  absl::StatusOr<std::string> proto_params_serialization =
      Cecpq2AeadHkdfKeyFormatStruct::GetParser().SerializeIntoString(
          proto_key_format);
  if (!proto_params_serialization.ok()) {
    return proto_params_serialization.status();
  }

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  return ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, *proto_params_serialization);
}

absl::StatusOr<Cecpq2PublicKey> ParsePublicKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing Cecpq2PublicKey.");
  }

  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  absl::StatusOr<Cecpq2AeadHkdfPublicKeyStruct> proto_key =
      Cecpq2AeadHkdfPublicKeyStruct::GetParser().Parse(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!proto_key.ok()) {
    return proto_key.status();
  }
  if (proto_key->version != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 keys are accepted for Cecpq2AeadHkdfPublicKey proto.");
  }

  absl::StatusOr<Cecpq2Parameters> parameters =
      ToParameters(proto_key->params, serialization.GetOutputPrefixTypeEnum());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return ToPublicKey(*parameters, *proto_key, serialization.IdRequirement());
}

absl::StatusOr<ProtoKeySerialization> SerializePublicKey(
    const Cecpq2PublicKey& public_key,
    absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<Cecpq2AeadHkdfParamsStruct> proto_params =
      FromParameters(public_key.GetParameters());
  if (!proto_params.ok()) {
    return proto_params.status();
  }

  absl::StatusOr<Cecpq2AeadHkdfPublicKeyStruct> proto_key =
      FromPublicKey(*proto_params, public_key);
  if (!proto_key.ok()) {
    return proto_key.status();
  }

  absl::StatusOr<std::string> serialized_proto_key =
      Cecpq2AeadHkdfPublicKeyStruct::GetParser().SerializeIntoString(
          *proto_key);
  if (!serialized_proto_key.ok()) {
    return serialized_proto_key.status();
  }
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(public_key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output =
      RestrictedData(*serialized_proto_key, InsecureSecretKeyAccess::Get());
  return ProtoKeySerialization::Create(
      kPublicTypeUrl, restricted_output, KeyMaterialTypeEnum::kAsymmetricPublic,
      *output_prefix_type, public_key.GetIdRequirement());
}

absl::StatusOr<Cecpq2PrivateKey> ParsePrivateKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError(
        "Parsing private key requires secret key access.");
  }
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing Cecpq2PrivateKey.");
  }

  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  absl::StatusOr<Cecpq2AeadHkdfPrivateKeyStruct> proto_key =
      Cecpq2AeadHkdfPrivateKeyStruct::GetParser().Parse(
          restricted_data.GetSecret(*token));
  if (!proto_key.ok()) {
    return proto_key.status();
  }
  if (proto_key->public_key.version != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 keys are accepted for Cecpq2AeadHkdfPublicKey proto.");
  }
  if (proto_key->version != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 keys are accepted for Cecpq2AeadHkdfPrivateKey proto.");
  }

  absl::StatusOr<Cecpq2Parameters> parameters = ToParameters(
      proto_key->public_key.params, serialization.GetOutputPrefixTypeEnum());
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<Cecpq2PublicKey> public_key = ToPublicKey(
      *parameters, proto_key->public_key, serialization.IdRequirement());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return ToPrivateKey(*public_key, *proto_key);
}

Cecpq2ProtoParametersParserImpl* Cecpq2ProtoParametersParser() {
  static auto* parser =
      new Cecpq2ProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return parser;
}

Cecpq2ProtoParametersSerializerImpl* Cecpq2ProtoParametersSerializer() {
  static auto* serializer = new Cecpq2ProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return serializer;
}

Cecpq2ProtoPublicKeyParserImpl* Cecpq2ProtoPublicKeyParser() {
  static auto* parser =
      new Cecpq2ProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return parser;
}

Cecpq2ProtoPublicKeySerializerImpl* Cecpq2ProtoPublicKeySerializer() {
  static auto* serializer =
      new Cecpq2ProtoPublicKeySerializerImpl(SerializePublicKey);
  return serializer;
}

Cecpq2ProtoPrivateKeyParserImpl* Cecpq2ProtoPrivateKeyParser() {
  static auto* parser =
      new Cecpq2ProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return parser;
}

}  // namespace

absl::Status RegisterCecpq2ProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(Cecpq2ProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      registry.RegisterParametersSerializer(Cecpq2ProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(Cecpq2ProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeySerializer(Cecpq2ProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeyParser(Cecpq2ProtoPrivateKeyParser());
}

absl::Status RegisterCecpq2ProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(Cecpq2ProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      builder.RegisterParametersSerializer(Cecpq2ProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(Cecpq2ProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeySerializer(Cecpq2ProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeyParser(Cecpq2ProtoPrivateKeyParser());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
