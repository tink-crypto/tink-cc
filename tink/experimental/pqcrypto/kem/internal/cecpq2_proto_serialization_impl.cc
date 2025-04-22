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

#include <memory>
#include <string>

#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_parameters.h"
#include "tink/internal/common_proto_enums.h"
#include "tink/internal/global_serialization_registry.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/proto_parser.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/parameters.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using Cecpq2ProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, Cecpq2Parameters>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.Cecpq2AeadHkdfPrivateKey";

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

Cecpq2ProtoParametersParserImpl* Cecpq2ProtoParametersParser() {
  static auto* parser =
      new Cecpq2ProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return parser;
}

}  // namespace

absl::Status RegisterCecpq2ProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  return registry.RegisterParametersParser(Cecpq2ProtoParametersParser());
}

absl::Status RegisterCecpq2ProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  return builder.RegisterParametersParser(Cecpq2ProtoParametersParser());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
