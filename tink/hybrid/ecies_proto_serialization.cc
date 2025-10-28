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

#include "tink/hybrid/ecies_proto_serialization.h"

#include <cstdint>
#include <string>

#include "absl/base/attributes.h"
#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/internal/aes_ctr_hmac_proto_structs.h"
#include "tink/aead/internal/aes_gcm_proto_format.h"
#include "tink/aead/internal/xchacha20_poly1305_proto_format.h"
#include "tink/big_integer.h"
#include "tink/daead/internal/aes_siv_proto_format.h"
#include "tink/ec_point.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_private_key.h"
#include "tink/hybrid/ecies_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_encoding_util.h"
#include "tink/internal/common_proto_enums.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/proto_parser.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/mac/internal/hmac_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretDataFromStringView;

struct EciesHkdfKemParamsStruct {
  internal::EllipticCurveTypeEnum curve_type;
  internal::HashTypeEnum hkdf_hash_type;
  std::string hkdf_salt;

  static ProtoParser<EciesHkdfKemParamsStruct> CreateParser() {
    return ProtoParserBuilder<EciesHkdfKemParamsStruct>()
        .AddEnumField(1, &EciesHkdfKemParamsStruct::curve_type,
                      &internal::EllipticCurveTypeEnumIsValid)
        .AddEnumField(2, &EciesHkdfKemParamsStruct::hkdf_hash_type,
                      &internal::HashTypeEnumIsValid)
        .AddBytesStringField(11, &EciesHkdfKemParamsStruct::hkdf_salt)
        .BuildOrDie();
  }
};

struct EciesAeadDemParamsStruct {
  internal::KeyTemplateStruct aead_dem;

  static ProtoParser<EciesAeadDemParamsStruct> CreateParser() {
    return ProtoParserBuilder<EciesAeadDemParamsStruct>()
        .AddMessageField(2, &EciesAeadDemParamsStruct::aead_dem,
                         internal::KeyTemplateStruct::CreateParser())
        .BuildOrDie();
  }
};

struct EciesAeadHkdfParamsStruct {
  EciesHkdfKemParamsStruct kem_params;
  EciesAeadDemParamsStruct dem_params;
  internal::EcPointFormatEnum ec_point_format;

  static ProtoParser<EciesAeadHkdfParamsStruct> CreateParser() {
    return ProtoParserBuilder<EciesAeadHkdfParamsStruct>()
        .AddMessageField(1, &EciesAeadHkdfParamsStruct::kem_params,
                         EciesHkdfKemParamsStruct::CreateParser())
        .AddMessageField(2, &EciesAeadHkdfParamsStruct::dem_params,
                         EciesAeadDemParamsStruct::CreateParser())
        .AddEnumField(3, &EciesAeadHkdfParamsStruct::ec_point_format,
                      &internal::EcPointFormatEnumIsValid)
        .BuildOrDie();
  }
};

struct EciesAeadHkdfPublicKeyStruct {
  uint32_t version;
  EciesAeadHkdfParamsStruct params;
  std::string x;
  std::string y;

  static ProtoParser<EciesAeadHkdfPublicKeyStruct> CreateParser() {
    return ProtoParserBuilder<EciesAeadHkdfPublicKeyStruct>()
        .AddUint32Field(1, &EciesAeadHkdfPublicKeyStruct::version)
        .AddMessageField(2, &EciesAeadHkdfPublicKeyStruct::params,
                         EciesAeadHkdfParamsStruct::CreateParser())
        .AddBytesStringField(3, &EciesAeadHkdfPublicKeyStruct::x)
        .AddBytesStringField(4, &EciesAeadHkdfPublicKeyStruct::y)
        .BuildOrDie();
  }

  static const ProtoParser<EciesAeadHkdfPublicKeyStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<EciesAeadHkdfPublicKeyStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

struct EciesAeadHkdfPrivateKeyStruct {
  uint32_t version;
  EciesAeadHkdfPublicKeyStruct public_key;
  SecretData key_value;

  static ProtoParser<EciesAeadHkdfPrivateKeyStruct> CreateParser() {
    return ProtoParserBuilder<EciesAeadHkdfPrivateKeyStruct>()
        .AddUint32Field(1, &EciesAeadHkdfPrivateKeyStruct::version)
        .AddMessageField(2, &EciesAeadHkdfPrivateKeyStruct::public_key,
                         EciesAeadHkdfPublicKeyStruct::CreateParser())
        .AddBytesSecretDataField(3, &EciesAeadHkdfPrivateKeyStruct::key_value)
        .BuildOrDie();
  }

  static const ProtoParser<EciesAeadHkdfPrivateKeyStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<EciesAeadHkdfPrivateKeyStruct>>
        parser{CreateParser()};
    return *parser;
  }
};

struct EciesAeadHkdfKeyFormatStruct {
  EciesAeadHkdfParamsStruct params;

  static ProtoParser<EciesAeadHkdfKeyFormatStruct> CreateParser() {
    return ProtoParserBuilder<EciesAeadHkdfKeyFormatStruct>()
        .AddMessageField(1, &EciesAeadHkdfKeyFormatStruct::params,
                         EciesAeadHkdfParamsStruct::CreateParser())
        .BuildOrDie();
  }

  static const ProtoParser<EciesAeadHkdfKeyFormatStruct>& GetParser() {
    static absl::NoDestructor<ProtoParser<EciesAeadHkdfKeyFormatStruct>> parser{
        CreateParser()};
    return *parser;
  }
};

using EciesProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   EciesParameters>;
using EciesProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<EciesParameters,
                                       internal::ProtoParametersSerialization>;
using EciesProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, EciesPublicKey>;
using EciesProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<EciesPublicKey,
                                internal::ProtoKeySerialization>;
using EciesProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, EciesPrivateKey>;
using EciesProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<EciesPrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";
const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";

absl::StatusOr<EciesParameters::Variant> ToVariant(
    internal::OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case internal::OutputPrefixTypeEnum::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case internal::OutputPrefixTypeEnum::kCrunchy:
      return EciesParameters::Variant::kCrunchy;
    case internal::OutputPrefixTypeEnum::kRaw:
      return EciesParameters::Variant::kNoPrefix;
    case internal::OutputPrefixTypeEnum::kTink:
      return EciesParameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine EciesParameters::Variant");
  }
}

absl::StatusOr<internal::OutputPrefixTypeEnum> ToOutputPrefixType(
    EciesParameters::Variant variant) {
  switch (variant) {
    case EciesParameters::Variant::kCrunchy:
      return internal::OutputPrefixTypeEnum::kCrunchy;
    case EciesParameters::Variant::kNoPrefix:
      return internal::OutputPrefixTypeEnum::kRaw;
    case EciesParameters::Variant::kTink:
      return internal::OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type.");
  }
}

bool IsNistCurve(EciesParameters::CurveType curve) {
  return curve == EciesParameters::CurveType::kNistP256 ||
         curve == EciesParameters::CurveType::kNistP384 ||
         curve == EciesParameters::CurveType::kNistP521;
}

absl::StatusOr<EciesParameters::CurveType> FromProtoCurveType(
    internal::EllipticCurveTypeEnum curve) {
  switch (curve) {
    case internal::EllipticCurveTypeEnum::kNistP256:
      return EciesParameters::CurveType::kNistP256;
    case internal::EllipticCurveTypeEnum::kNistP384:
      return EciesParameters::CurveType::kNistP384;
    case internal::EllipticCurveTypeEnum::kNistP521:
      return EciesParameters::CurveType::kNistP521;
    case internal::EllipticCurveTypeEnum::kCurve25519:
      return EciesParameters::CurveType::kX25519;
    default:
      return absl::InvalidArgumentError(
          "Could not determine EciesParameters::CurveType.");
  }
}

absl::StatusOr<internal::EllipticCurveTypeEnum> ToProtoCurveType(
    EciesParameters::CurveType curve) {
  switch (curve) {
    case EciesParameters::CurveType::kNistP256:
      return internal::EllipticCurveTypeEnum::kNistP256;
    case EciesParameters::CurveType::kNistP384:
      return internal::EllipticCurveTypeEnum::kNistP384;
    case EciesParameters::CurveType::kNistP521:
      return internal::EllipticCurveTypeEnum::kNistP521;
    case EciesParameters::CurveType::kX25519:
      return internal::EllipticCurveTypeEnum::kCurve25519;
    default:
      return absl::InvalidArgumentError("Could not determine curve type.");
  }
}

absl::StatusOr<EciesParameters::HashType> FromProtoHashType(
    internal::HashTypeEnum hash) {
  switch (hash) {
    case internal::HashTypeEnum::kSha1:
      return EciesParameters::HashType::kSha1;
    case internal::HashTypeEnum::kSha224:
      return EciesParameters::HashType::kSha224;
    case internal::HashTypeEnum::kSha256:
      return EciesParameters::HashType::kSha256;
    case internal::HashTypeEnum::kSha384:
      return EciesParameters::HashType::kSha384;
    case internal::HashTypeEnum::kSha512:
      return EciesParameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine EciesParameters::HashType.");
  }
}

absl::StatusOr<internal::HashTypeEnum> ToProtoHashType(
    EciesParameters::HashType hash) {
  switch (hash) {
    case EciesParameters::HashType::kSha1:
      return internal::HashTypeEnum::kSha1;
    case EciesParameters::HashType::kSha224:
      return internal::HashTypeEnum::kSha224;
    case EciesParameters::HashType::kSha256:
      return internal::HashTypeEnum::kSha256;
    case EciesParameters::HashType::kSha384:
      return internal::HashTypeEnum::kSha384;
    case EciesParameters::HashType::kSha512:
      return internal::HashTypeEnum::kSha512;
    default:
      return absl::InvalidArgumentError("Could not determine hash type.");
  }
}

absl::StatusOr<EciesParameters::PointFormat> FromProtoPointFormat(
    internal::EcPointFormatEnum format) {
  switch (format) {
    case internal::EcPointFormatEnum::kCompressed:
      return EciesParameters::PointFormat::kCompressed;
    case internal::EcPointFormatEnum::kUncompressed:
      return EciesParameters::PointFormat::kUncompressed;
    case internal::EcPointFormatEnum::kDoNotUseCrunchyUncompressed:
      return EciesParameters::PointFormat::kLegacyUncompressed;
    default:
      return absl::InvalidArgumentError(
          "Could not determine EciesParameters::PointFormat.");
  }
}

absl::StatusOr<internal::EcPointFormatEnum> ToProtoPointFormat(
    EciesParameters::PointFormat format) {
  switch (format) {
    case EciesParameters::PointFormat::kCompressed:
      return internal::EcPointFormatEnum::kCompressed;
    case EciesParameters::PointFormat::kUncompressed:
      return internal::EcPointFormatEnum::kUncompressed;
    case EciesParameters::PointFormat::kLegacyUncompressed:
      return internal::EcPointFormatEnum::kDoNotUseCrunchyUncompressed;
    default:
      return absl::InvalidArgumentError("Could not determine point format.");
  }
}

absl::Status ValidateAesCtrHmacAeadKeyFormat(
    const internal::ProtoAesCtrHmacAeadKeyFormat& format) {
  if (format.aes_ctr_key_format().params().iv_size() != 16) {
    return absl::InvalidArgumentError("IV size must be 16 bytes.");
  }
  if (format.hmac_key_format().version() != 0) {
    return absl::InvalidArgumentError("HMAC key format version must be 0.");
  }
  if (format.hmac_key_format().key_size() != 32) {
    return absl::InvalidArgumentError("HMAC key size must be 32 bytes.");
  }
  if (format.hmac_key_format().params().hash() !=
      internal::HashTypeEnum::kSha256) {
    return absl::InvalidArgumentError("Hash type must be SHA256.");
  }
  if (format.aes_ctr_key_format().key_size() !=
      format.hmac_key_format().params().tag_size()) {
    return absl::InvalidArgumentError(
        "Allowed AES-CTR-HMAC DEMs must have matching key and tag sizes.");
  }
  return absl::OkStatus();
}

absl::StatusOr<EciesParameters::DemId> FromProtoDemParams(
    const EciesAeadDemParamsStruct& proto_dem_params) {
  if (proto_dem_params.aead_dem.type_url ==
      "type.googleapis.com/google.crypto.tink.AesGcmKey") {
    internal::ProtoAesGcmKeyFormat key_format;
    if (!key_format.ParseFromString(proto_dem_params.aead_dem.value)) {
      return absl::InvalidArgumentError("Failed to parse AesGcmKey proto");
    }
    switch (key_format.key_size()) {
      case 16:
        return EciesParameters::DemId::kAes128GcmRaw;
      case 32:
        return EciesParameters::DemId::kAes256GcmRaw;
      default:
        return absl::InvalidArgumentError(absl::StrFormat(
            "Invalid AES-GCM key length for DEM: %d, want 16 or 32 bytes.",
            key_format.key_size()));
    }
  }
  if (proto_dem_params.aead_dem.type_url ==
      "type.googleapis.com/google.crypto.tink.AesSivKey") {
    internal::ProtoAesSivKeyFormat aes_siv_key_format;
    if (!aes_siv_key_format.ParseFromString(proto_dem_params.aead_dem.value)) {
      return absl::InvalidArgumentError(
          "Failed to parse AesSivKeyFormat proto");
    }
    if (aes_siv_key_format.key_size() == 64) {
      return EciesParameters::DemId::kAes256SivRaw;
    }
    return absl::InvalidArgumentError("Invalid AES-SIV key length for DEM.");
  }
  if (proto_dem_params.aead_dem.type_url ==
          "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key" ||
      // TODO: b/330508549 - Remove type URL exception for an existing key.
      proto_dem_params.aead_dem.type_url ==
          "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305KeyFormat") {
    internal::ProtoXChaCha20Poly1305KeyFormat format;
    if (!format.ParseFromString(proto_dem_params.aead_dem.value)) {
      return absl::InvalidArgumentError(
          "Failed to parse XChaCha20Poly1305Key proto");
    }
    return EciesParameters::DemId::kXChaCha20Poly1305Raw;
  }
  if (proto_dem_params.aead_dem.type_url ==
      "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey") {
    internal::ProtoAesCtrHmacAeadKeyFormat aes_ctr_hmac_aead_key_format;
    if (!aes_ctr_hmac_aead_key_format.ParseFromString(
            proto_dem_params.aead_dem.value)) {
      return absl::InvalidArgumentError(
          "Could not parse AES-CTR-HMAC key format");
    }
    absl::Status format_validation =
        ValidateAesCtrHmacAeadKeyFormat(aes_ctr_hmac_aead_key_format);
    if (!format_validation.ok()) {
      return format_validation;
    }
    if (aes_ctr_hmac_aead_key_format.aes_ctr_key_format().key_size() == 16) {
      return EciesParameters::DemId::kAes128CtrHmacSha256Raw;
    }
    if (aes_ctr_hmac_aead_key_format.aes_ctr_key_format().key_size() == 32) {
      return EciesParameters::DemId::kAes256CtrHmacSha256Raw;
    }
    return absl::InvalidArgumentError(
        "Invalid AES-CTR-HMAC key length for DEM.");
  }
  return absl::InvalidArgumentError(
      "Unable to convert proto DEM params to DEM id.");
}

EciesAeadDemParamsStruct CreateEciesAeadDemParamsStruct(
    absl::string_view type_url, const std::string& serialized_key_format) {
  EciesAeadDemParamsStruct dem_params;
  dem_params.aead_dem.type_url = std::string(type_url);
  dem_params.aead_dem.output_prefix_type =
      internal::OutputPrefixTypeEnum::kTink;
  dem_params.aead_dem.value = serialized_key_format;
  return dem_params;
}

absl::StatusOr<EciesAeadDemParamsStruct> ToProtoDemParams(
    EciesParameters::DemId dem_id) {
  if (dem_id == EciesParameters::DemId::kAes128GcmRaw ||
      dem_id == EciesParameters::DemId::kAes256GcmRaw) {
    int key_size = (dem_id == EciesParameters::DemId::kAes128GcmRaw) ? 16 : 32;
    internal::ProtoAesGcmKeyFormat key_format;
    key_format.set_version(0);
    key_format.set_key_size(key_size);
    return CreateEciesAeadDemParamsStruct(
        "type.googleapis.com/google.crypto.tink.AesGcmKey",
        key_format.SerializeAsString());
  }
  if (dem_id == EciesParameters::DemId::kAes256SivRaw) {
    internal::ProtoAesSivKeyFormat format;
    format.set_version(0);
    format.set_key_size(64);
    return CreateEciesAeadDemParamsStruct(
        "type.googleapis.com/google.crypto.tink.AesSivKey",
        format.SerializeAsString());
  }
  if (dem_id == EciesParameters::DemId::kXChaCha20Poly1305Raw) {
    internal::ProtoXChaCha20Poly1305KeyFormat format;
    format.set_version(0);
    std::string serialized_proto = format.SerializeAsString();
    return CreateEciesAeadDemParamsStruct(
        "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key",
        serialized_proto);
  }
  if (dem_id == EciesParameters::DemId::kAes128CtrHmacSha256Raw ||
      dem_id == EciesParameters::DemId::kAes256CtrHmacSha256Raw) {
    const int key_size =
        (dem_id == EciesParameters::DemId::kAes128CtrHmacSha256Raw) ? 16 : 32;
    const int tag_size = key_size;  // Allowed DEMs have matching key/tag sizes.

    internal::ProtoAesCtrHmacAeadKeyFormat format;
    format.mutable_aes_ctr_key_format()->set_key_size(key_size);
    format.mutable_aes_ctr_key_format()->mutable_params()->set_iv_size(16);
    format.mutable_hmac_key_format()->set_version(0);
    format.mutable_hmac_key_format()->set_key_size(32);
    format.mutable_hmac_key_format()->mutable_params()->set_tag_size(tag_size);
    format.mutable_hmac_key_format()->mutable_params()->set_hash(
        internal::HashTypeEnum::kSha256);

    return CreateEciesAeadDemParamsStruct(
        "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
        format.SerializeAsString());
  }
  return absl::InvalidArgumentError(
      "Unable to convert DEM id to proto DEM params.");
}

absl::StatusOr<EciesParameters> ToParameters(
    internal::OutputPrefixTypeEnum output_prefix_type,
    const EciesAeadHkdfParamsStruct& params) {
  absl::StatusOr<EciesParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<EciesParameters::CurveType> curve_type =
      FromProtoCurveType(params.kem_params.curve_type);
  if (!curve_type.ok()) {
    return curve_type.status();
  }

  absl::StatusOr<EciesParameters::HashType> hash_type =
      FromProtoHashType(params.kem_params.hkdf_hash_type);
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  absl::StatusOr<EciesParameters::DemId> dem_id =
      FromProtoDemParams(params.dem_params);
  if (!dem_id.ok()) {
    return dem_id.status();
  }

  EciesParameters::Builder builder = EciesParameters::Builder()
                                         .SetVariant(*variant)
                                         .SetCurveType(*curve_type)
                                         .SetHashType(*hash_type)
                                         .SetDemId(*dem_id);

  if (IsNistCurve(*curve_type)) {
    absl::StatusOr<EciesParameters::PointFormat> point_format =
        FromProtoPointFormat(params.ec_point_format);
    if (!point_format.ok()) {
      return point_format.status();
    }
    builder.SetNistCurvePointFormat(*point_format);
  }

  if (!params.kem_params.hkdf_salt.empty()) {
    builder.SetSalt(params.kem_params.hkdf_salt);
  }

  return builder.Build();
}

absl::StatusOr<EciesAeadHkdfParamsStruct> FromParameters(
    const EciesParameters& parameters) {
  absl::StatusOr<internal::EllipticCurveTypeEnum> curve_type =
      ToProtoCurveType(parameters.GetCurveType());
  if (!curve_type.ok()) {
    return curve_type.status();
  }

  absl::StatusOr<internal::HashTypeEnum> hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  absl::StatusOr<EciesAeadDemParamsStruct> dem_params =
      ToProtoDemParams(parameters.GetDemId());
  if (!dem_params.ok()) {
    return dem_params.status();
  }

  EciesAeadHkdfParamsStruct params;
  params.dem_params = *dem_params;
  params.kem_params.curve_type = *curve_type;
  params.kem_params.hkdf_hash_type = *hash_type;
  if (parameters.GetSalt().has_value()) {
    params.kem_params.hkdf_salt = std::string(*parameters.GetSalt());
  }
  if (parameters.GetNistCurvePointFormat().has_value()) {
    absl::StatusOr<internal::EcPointFormatEnum> ec_point_format =
        ToProtoPointFormat(*parameters.GetNistCurvePointFormat());
    if (!ec_point_format.ok()) {
      return ec_point_format.status();
    }
    params.ec_point_format = *ec_point_format;
  } else {
    // Must be X25519, so set to the compressed format.
    params.ec_point_format = internal::EcPointFormatEnum::kCompressed;
  }

  return params;
}

absl::StatusOr<EciesPublicKey> ToPublicKey(
    const EciesParameters& parameters,
    const EciesAeadHkdfPublicKeyStruct& proto_key,
    absl::optional<int> id_requirement) {
  if (IsNistCurve(parameters.GetCurveType())) {
    EcPoint point(BigInteger(proto_key.x), BigInteger(proto_key.y));
    return EciesPublicKey::CreateForNistCurve(parameters, point, id_requirement,
                                              GetPartialKeyAccess());
  }
  return EciesPublicKey::CreateForCurveX25519(
      parameters, proto_key.x, id_requirement, GetPartialKeyAccess());
}

absl::StatusOr<int> GetEncodingLength(EciesParameters::CurveType curve) {
  // Encode EC field elements with extra leading zero byte for compatibility
  // with Java BigInteger decoding (b/264525021).
  switch (curve) {
    case EciesParameters::CurveType::kNistP256:
      return 33;
    case EciesParameters::CurveType::kNistP384:
      return 49;
    case EciesParameters::CurveType::kNistP521:
      return 67;
    default:
      return absl::InvalidArgumentError(
          "Cannot determine encoding length for curve.");
  }
}

absl::StatusOr<EciesAeadHkdfPublicKeyStruct> FromPublicKey(
    const EciesAeadHkdfParamsStruct& params, const EciesPublicKey& public_key) {
  EciesAeadHkdfPublicKeyStruct proto_key;
  proto_key.version = 0;
  proto_key.params = params;
  if (public_key.GetNistCurvePoint(GetPartialKeyAccess()).has_value()) {
    EcPoint point = *public_key.GetNistCurvePoint(GetPartialKeyAccess());
    absl::StatusOr<int> encoding_length =
        GetEncodingLength(public_key.GetParameters().GetCurveType());
    if (!encoding_length.ok()) {
      return encoding_length.status();
    }
    absl::StatusOr<std::string> x = internal::GetValueOfFixedLength(
        point.GetX().GetValue(), *encoding_length);
    if (!x.ok()) {
      return x.status();
    }
    absl::StatusOr<std::string> y = internal::GetValueOfFixedLength(
        point.GetY().GetValue(), *encoding_length);
    if (!y.ok()) {
      return y.status();
    }
    proto_key.x = *x;
    proto_key.y = *y;
  } else {
    if (!public_key.GetX25519CurvePointBytes(GetPartialKeyAccess())
             .has_value()) {
      return absl::InvalidArgumentError(
          "X25519 public key missing point bytes.");
    }
    proto_key.x = std::string(
        *public_key.GetX25519CurvePointBytes(GetPartialKeyAccess()));
    proto_key.y = "";
  }
  return proto_key;
}

absl::StatusOr<EciesParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  const internal::KeyTemplateStruct key_template_struct =
      serialization.GetKeyTemplateStruct();
  if (key_template_struct.type_url != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing EciesParameters.");
  }

  absl::StatusOr<EciesAeadHkdfKeyFormatStruct> proto_key_format =
      EciesAeadHkdfKeyFormatStruct::GetParser().Parse(
          key_template_struct.value);
  if (!proto_key_format.ok()) {
    return proto_key_format.status();
  }

  return ToParameters(key_template_struct.output_prefix_type,
                      proto_key_format->params);
}

absl::StatusOr<EciesPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing EciesAeadHkdfPublicKey.");
  }

  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  absl::StatusOr<EciesAeadHkdfPublicKeyStruct> proto_key =
      EciesAeadHkdfPublicKeyStruct::GetParser().Parse(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!proto_key.ok()) {
    return proto_key.status();
  }
  if (proto_key->version != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 keys are accepted for EciesAeadHkdfPublicKey proto.");
  }

  absl::StatusOr<EciesParameters> parameters =
      ToParameters(serialization.GetOutputPrefixTypeEnum(), proto_key->params);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return ToPublicKey(*parameters, *proto_key, serialization.IdRequirement());
}

absl::StatusOr<EciesPrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing EciesAeadHkdfPrivateKey.");
  }
  absl::StatusOr<EciesAeadHkdfPrivateKeyStruct> proto_key =
      EciesAeadHkdfPrivateKeyStruct::GetParser().Parse(SecretDataAsStringView(
          serialization.SerializedKeyProto().Get(*token)));
  if (!proto_key.ok()) {
    return proto_key.status();
  }
  if (proto_key->version != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 keys are accepted for EciesAeadHkdfPrivateKey proto.");
  }

  if (proto_key->public_key.version != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 public keys are accepted for "
        "EciesAeadHkdfPrivateKey proto.");
  }

  const internal::OutputPrefixTypeEnum output_prefix_type =
      serialization.GetOutputPrefixTypeEnum();

  absl::StatusOr<EciesParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<EciesParameters> parameters =
      ToParameters(output_prefix_type, proto_key->public_key.params);
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<EciesPublicKey> public_key = ToPublicKey(
      *parameters, proto_key->public_key, serialization.IdRequirement());
  if (!public_key.ok()) {
    return public_key.status();
  }

  if (IsNistCurve(parameters->GetCurveType())) {
    return EciesPrivateKey::CreateForNistCurve(
        *public_key, RestrictedBigInteger(proto_key->key_value, *token),
        GetPartialKeyAccess());
  }

  return EciesPrivateKey::CreateForCurveX25519(
      *public_key, RestrictedData(proto_key->key_value, *token),
      GetPartialKeyAccess());
}

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const EciesParameters& parameters) {
  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<EciesAeadHkdfParamsStruct> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }
  EciesAeadHkdfKeyFormatStruct proto_key_format;
  proto_key_format.params = *params;

  absl::StatusOr<std::string> s =
      EciesAeadHkdfKeyFormatStruct::GetParser().SerializeIntoString(
          proto_key_format);
  if (!s.ok()) {
    return s.status();
  }
  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, *s);
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const EciesPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<EciesAeadHkdfParamsStruct> params =
      FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  absl::StatusOr<EciesAeadHkdfPublicKeyStruct> proto_key =
      FromPublicKey(*params, key);
  if (!proto_key.ok()) {
    return proto_key.status();
  }

  absl::StatusOr<std::string> serialized_proto_key =
      EciesAeadHkdfPublicKeyStruct::GetParser().SerializeIntoString(*proto_key);
  if (!serialized_proto_key.ok()) {
    return serialized_proto_key.status();
  }
  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output =
      RestrictedData(*serialized_proto_key, InsecureSecretKeyAccess::Get());
  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl, restricted_output,
      internal::KeyMaterialTypeEnum::kAsymmetricPublic, *output_prefix_type,
      key.GetIdRequirement());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePrivateKey(
    const EciesPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  absl::StatusOr<EciesAeadHkdfParamsStruct> params =
      FromParameters(key.GetPublicKey().GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  absl::StatusOr<EciesAeadHkdfPublicKeyStruct> proto_public_key =
      FromPublicKey(*params, key.GetPublicKey());
  if (!proto_public_key.ok()) {
    return proto_public_key.status();
  }

  EciesAeadHkdfPrivateKeyStruct proto_private_key;
  proto_private_key.version = 0;
  proto_private_key.public_key = *proto_public_key;
  if (IsNistCurve(key.GetPublicKey().GetParameters().GetCurveType())) {
    absl::StatusOr<int> encoding_length =
        GetEncodingLength(key.GetPublicKey().GetParameters().GetCurveType());
    if (!encoding_length.ok()) {
      return encoding_length.status();
    }
    absl::optional<RestrictedBigInteger> secret =
        key.GetNistPrivateKeyValue(GetPartialKeyAccess());
    if (!secret.has_value()) {
      return absl::InternalError(
          "NIST private key is missing NIST private key value.");
    }
    absl::StatusOr<SecretData> key_value =
        internal::GetSecretValueOfFixedLength(*secret, *encoding_length,
                                              InsecureSecretKeyAccess::Get());
    if (!key_value.ok()) {
      return key_value.status();
    }
    proto_private_key.key_value = *key_value;
  } else {
    absl::optional<RestrictedData> secret =
        key.GetX25519PrivateKeyBytes(GetPartialKeyAccess());
    if (!secret.has_value()) {
      return absl::InternalError(
          "X25519 private key is missing X25519 private key bytes.");
    }
    proto_private_key.key_value = SecretDataFromStringView(
        secret->GetSecret(InsecureSecretKeyAccess::Get()));
  }

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<SecretData> serialized_proto_private_key =
      EciesAeadHkdfPrivateKeyStruct::GetParser().SerializeIntoSecretData(
          proto_private_key);
  if (!serialized_proto_private_key.ok()) {
    return serialized_proto_private_key.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*serialized_proto_private_key, *token);
  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl, restricted_output,
      internal::KeyMaterialTypeEnum::kAsymmetricPrivate, *output_prefix_type,
      key.GetIdRequirement());
}

EciesProtoParametersParserImpl* EciesProtoParametersParser() {
  static auto* parser =
      new EciesProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return parser;
}

EciesProtoParametersSerializerImpl* EciesProtoParametersSerializer() {
  static auto* serializer = new EciesProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return serializer;
}

EciesProtoPublicKeyParserImpl* EciesProtoPublicKeyParser() {
  static auto* parser =
      new EciesProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return parser;
}

EciesProtoPublicKeySerializerImpl* EciesProtoPublicKeySerializer() {
  static auto* serializer =
      new EciesProtoPublicKeySerializerImpl(SerializePublicKey);
  return serializer;
}

EciesProtoPrivateKeyParserImpl* EciesProtoPrivateKeyParser() {
  static auto* parser =
      new EciesProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return parser;
}

EciesProtoPrivateKeySerializerImpl* EciesProtoPrivateKeySerializer() {
  static auto* serializer =
      new EciesProtoPrivateKeySerializerImpl(SerializePrivateKey);
  return serializer;
}

}  // namespace

absl::Status RegisterEciesProtoSerialization() {
  absl::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(EciesProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(EciesProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(EciesProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeySerializer(EciesProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(EciesProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(EciesProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
