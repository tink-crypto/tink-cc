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

#include "tink/hybrid/internal/ecies_proto_serialization_impl.h"

#include <array>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
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
#include "tink/internal/proto_parser_enum_field.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"
#include "tink/internal/proto_parser_secret_data_field.h"
#include "tink/internal/serialization_registry.h"
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
namespace internal {
namespace {

using ::crypto::tink::internal::KeyTemplateTP;
using ::crypto::tink::internal::proto_parsing::BytesField;
using ::crypto::tink::internal::proto_parsing::EnumField;
using ::crypto::tink::internal::proto_parsing::Field;
using ::crypto::tink::internal::proto_parsing::Message;
using ::crypto::tink::internal::proto_parsing::MessageField;
using ::crypto::tink::internal::proto_parsing::SecretDataField;
using ::crypto::tink::internal::proto_parsing::Uint32Field;
using ::crypto::tink::util::SecretDataAsStringView;

class ProtoEciesHkdfKemParams : public Message {
 public:
  ProtoEciesHkdfKemParams() = default;
  using Message::SerializeAsString;

  EllipticCurveTypeEnum curve_type() const { return curve_type_.value(); }
  void set_curve_type(EllipticCurveTypeEnum curve_type) {
    curve_type_.set_value(curve_type);
  }

  HashTypeEnum hkdf_hash_type() const { return hkdf_hash_type_.value(); }
  void set_hkdf_hash_type(HashTypeEnum hkdf_hash_type) {
    hkdf_hash_type_.set_value(hkdf_hash_type);
  }

  const std::string& hkdf_salt() const { return hkdf_salt_.value(); }
  void set_hkdf_salt(absl::string_view hkdf_salt) {
    hkdf_salt_.set_value(hkdf_salt);
  }

 private:
  size_t num_fields() const override { return 3; }
  const Field* field(int i) const override {
    return std::array<const Field*, 3>{&curve_type_, &hkdf_hash_type_,
                                       &hkdf_salt_}[i];
  }

  EnumField<EllipticCurveTypeEnum> curve_type_{1,
                                               &EllipticCurveTypeEnumIsValid};
  EnumField<HashTypeEnum> hkdf_hash_type_{2, &HashTypeEnumIsValid};
  BytesField hkdf_salt_{11};
};

class ProtoEciesAeadDemParams : public Message {
 public:
  ProtoEciesAeadDemParams() = default;
  using Message::SerializeAsString;

  const KeyTemplateTP& aead_dem() const { return aead_dem_.value(); }
  KeyTemplateTP* mutable_aead_dem() { return aead_dem_.mutable_value(); }

 private:
  size_t num_fields() const override { return 1; }
  const Field* field(int i) const override {
    return std::array<const Field*, 1>{&aead_dem_}[i];
  }

  MessageField<KeyTemplateTP> aead_dem_{2};
};

class ProtoEciesAeadHkdfParams : public Message {
 public:
  ProtoEciesAeadHkdfParams() = default;
  using Message::SerializeAsString;

  const ProtoEciesHkdfKemParams& kem_params() const {
    return kem_params_.value();
  }
  ProtoEciesHkdfKemParams* mutable_kem_params() {
    return kem_params_.mutable_value();
  }

  const ProtoEciesAeadDemParams& dem_params() const {
    return dem_params_.value();
  }
  ProtoEciesAeadDemParams* mutable_dem_params() {
    return dem_params_.mutable_value();
  }

  EcPointFormatEnum ec_point_format() const { return ec_point_format_.value(); }
  void set_ec_point_format(EcPointFormatEnum ec_point_format) {
    ec_point_format_.set_value(ec_point_format);
  }

 private:
  size_t num_fields() const override { return 3; }
  const Field* field(int i) const override {
    return std::array<const Field*, 3>{&kem_params_, &dem_params_,
                                       &ec_point_format_}[i];
  }

  MessageField<ProtoEciesHkdfKemParams> kem_params_{1};
  MessageField<ProtoEciesAeadDemParams> dem_params_{2};
  EnumField<EcPointFormatEnum> ec_point_format_{3, &EcPointFormatEnumIsValid};
};

class ProtoEciesAeadHkdfPublicKey : public Message {
 public:
  ProtoEciesAeadHkdfPublicKey() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const ProtoEciesAeadHkdfParams& params() const { return params_.value(); }
  ProtoEciesAeadHkdfParams* mutable_params() { return params_.mutable_value(); }

  const std::string& x() const { return x_.value(); }
  void set_x(absl::string_view x) { x_.set_value(x); }

  const std::string& y() const { return y_.value(); }
  void set_y(absl::string_view y) { y_.set_value(y); }

 private:
  size_t num_fields() const override { return 4; }
  const Field* field(int i) const override {
    return std::array<const Field*, 4>{&version_, &params_, &x_, &y_}[i];
  }

  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  MessageField<ProtoEciesAeadHkdfParams> params_{2};
  BytesField x_{3};
  BytesField y_{4};
};

class ProtoEciesAeadHkdfPrivateKey : public Message {
 public:
  ProtoEciesAeadHkdfPrivateKey() = default;
  using Message::SerializeAsString;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t version) { version_.set_value(version); }

  const ProtoEciesAeadHkdfPublicKey& public_key() const {
    return public_key_.value();
  }
  ProtoEciesAeadHkdfPublicKey* mutable_public_key() {
    return public_key_.mutable_value();
  }

  const SecretData& key_value() const { return key_value_.value(); }
  void set_key_value(SecretData key_value) {
    *key_value_.mutable_value() = std::move(key_value);
  }

 private:
  size_t num_fields() const override { return 3; }
  const Field* field(int i) const override {
    return std::array<const Field*, 3>{&version_, &public_key_, &key_value_}[i];
  }

  Uint32Field version_{1, ProtoFieldOptions::kImplicit};
  MessageField<ProtoEciesAeadHkdfPublicKey> public_key_{2};
  SecretDataField key_value_{3};
};

class ProtoEciesAeadHkdfKeyFormat : public Message {
 public:
  ProtoEciesAeadHkdfKeyFormat() = default;
  using Message::SerializeAsString;

  const ProtoEciesAeadHkdfParams& params() const { return params_.value(); }
  ProtoEciesAeadHkdfParams* mutable_params() { return params_.mutable_value(); }

 private:
  size_t num_fields() const override { return 1; }
  const Field* field(int i) const override {
    return std::array<const Field*, 1>{&params_}[i];
  }

  MessageField<ProtoEciesAeadHkdfParams> params_{1};
};

using EciesProtoParametersParserImpl =
    ParametersParserImpl<ProtoParametersSerialization, EciesParameters>;
using EciesProtoParametersSerializerImpl =
    ParametersSerializerImpl<EciesParameters, ProtoParametersSerialization>;
using EciesProtoPublicKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, EciesPublicKey>;
using EciesProtoPublicKeySerializerImpl =
    KeySerializerImpl<EciesPublicKey, ProtoKeySerialization>;
using EciesProtoPrivateKeyParserImpl =
    KeyParserImpl<ProtoKeySerialization, EciesPrivateKey>;
using EciesProtoPrivateKeySerializerImpl =
    KeySerializerImpl<EciesPrivateKey, ProtoKeySerialization>;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";
const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";

absl::StatusOr<EciesParameters::Variant> ToVariant(
    OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeEnum::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case OutputPrefixTypeEnum::kCrunchy:
      return EciesParameters::Variant::kCrunchy;
    case OutputPrefixTypeEnum::kRaw:
      return EciesParameters::Variant::kNoPrefix;
    case OutputPrefixTypeEnum::kTink:
      return EciesParameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine EciesParameters::Variant");
  }
}

absl::StatusOr<OutputPrefixTypeEnum> ToOutputPrefixType(
    EciesParameters::Variant variant) {
  switch (variant) {
    case EciesParameters::Variant::kCrunchy:
      return OutputPrefixTypeEnum::kCrunchy;
    case EciesParameters::Variant::kNoPrefix:
      return OutputPrefixTypeEnum::kRaw;
    case EciesParameters::Variant::kTink:
      return OutputPrefixTypeEnum::kTink;
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
    EllipticCurveTypeEnum curve) {
  switch (curve) {
    case EllipticCurveTypeEnum::kNistP256:
      return EciesParameters::CurveType::kNistP256;
    case EllipticCurveTypeEnum::kNistP384:
      return EciesParameters::CurveType::kNistP384;
    case EllipticCurveTypeEnum::kNistP521:
      return EciesParameters::CurveType::kNistP521;
    case EllipticCurveTypeEnum::kCurve25519:
      return EciesParameters::CurveType::kX25519;
    default:
      return absl::InvalidArgumentError(
          "Could not determine EciesParameters::CurveType.");
  }
}

absl::StatusOr<EllipticCurveTypeEnum> ToProtoCurveType(
    EciesParameters::CurveType curve) {
  switch (curve) {
    case EciesParameters::CurveType::kNistP256:
      return EllipticCurveTypeEnum::kNistP256;
    case EciesParameters::CurveType::kNistP384:
      return EllipticCurveTypeEnum::kNistP384;
    case EciesParameters::CurveType::kNistP521:
      return EllipticCurveTypeEnum::kNistP521;
    case EciesParameters::CurveType::kX25519:
      return EllipticCurveTypeEnum::kCurve25519;
    default:
      return absl::InvalidArgumentError("Could not determine curve type.");
  }
}

absl::StatusOr<EciesParameters::HashType> FromProtoHashType(HashTypeEnum hash) {
  switch (hash) {
    case HashTypeEnum::kSha1:
      return EciesParameters::HashType::kSha1;
    case HashTypeEnum::kSha224:
      return EciesParameters::HashType::kSha224;
    case HashTypeEnum::kSha256:
      return EciesParameters::HashType::kSha256;
    case HashTypeEnum::kSha384:
      return EciesParameters::HashType::kSha384;
    case HashTypeEnum::kSha512:
      return EciesParameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError(
          "Could not determine EciesParameters::HashType.");
  }
}

absl::StatusOr<HashTypeEnum> ToProtoHashType(EciesParameters::HashType hash) {
  switch (hash) {
    case EciesParameters::HashType::kSha1:
      return HashTypeEnum::kSha1;
    case EciesParameters::HashType::kSha224:
      return HashTypeEnum::kSha224;
    case EciesParameters::HashType::kSha256:
      return HashTypeEnum::kSha256;
    case EciesParameters::HashType::kSha384:
      return HashTypeEnum::kSha384;
    case EciesParameters::HashType::kSha512:
      return HashTypeEnum::kSha512;
    default:
      return absl::InvalidArgumentError("Could not determine hash type.");
  }
}

absl::StatusOr<EciesParameters::PointFormat> FromProtoPointFormat(
    EcPointFormatEnum format) {
  switch (format) {
    case EcPointFormatEnum::kCompressed:
      return EciesParameters::PointFormat::kCompressed;
    case EcPointFormatEnum::kUncompressed:
      return EciesParameters::PointFormat::kUncompressed;
    case EcPointFormatEnum::kDoNotUseCrunchyUncompressed:
      return EciesParameters::PointFormat::kLegacyUncompressed;
    default:
      return absl::InvalidArgumentError(
          "Could not determine EciesParameters::PointFormat.");
  }
}

absl::StatusOr<EcPointFormatEnum> ToProtoPointFormat(
    EciesParameters::PointFormat format) {
  switch (format) {
    case EciesParameters::PointFormat::kCompressed:
      return EcPointFormatEnum::kCompressed;
    case EciesParameters::PointFormat::kUncompressed:
      return EcPointFormatEnum::kUncompressed;
    case EciesParameters::PointFormat::kLegacyUncompressed:
      return EcPointFormatEnum::kDoNotUseCrunchyUncompressed;
    default:
      return absl::InvalidArgumentError("Could not determine point format.");
  }
}

absl::Status ValidateAesCtrHmacAeadKeyFormat(
    const AesCtrHmacAeadKeyFormatTP& format) {
  if (format.aes_ctr_key_format().params().iv_size() != 16) {
    return absl::InvalidArgumentError("IV size must be 16 bytes.");
  }
  if (format.hmac_key_format().version() != 0) {
    return absl::InvalidArgumentError("HMAC key format version must be 0.");
  }
  if (format.hmac_key_format().key_size() != 32) {
    return absl::InvalidArgumentError("HMAC key size must be 32 bytes.");
  }
  if (format.hmac_key_format().params().hash() != HashTypeEnum::kSha256) {
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
    const ProtoEciesAeadDemParams& proto_dem_params) {
  if (proto_dem_params.aead_dem().type_url() ==
      "type.googleapis.com/google.crypto.tink.AesGcmKey") {
    AesGcmKeyFormatTP key_format;
    if (!key_format.ParseFromString(proto_dem_params.aead_dem().value())) {
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
  if (proto_dem_params.aead_dem().type_url() ==
      "type.googleapis.com/google.crypto.tink.AesSivKey") {
    AesSivKeyFormatTP aes_siv_key_format;
    if (!aes_siv_key_format.ParseFromString(
            proto_dem_params.aead_dem().value())) {
      return absl::InvalidArgumentError(
          "Failed to parse AesSivKeyFormat proto");
    }
    if (aes_siv_key_format.key_size() == 64) {
      return EciesParameters::DemId::kAes256SivRaw;
    }
    return absl::InvalidArgumentError("Invalid AES-SIV key length for DEM.");
  }
  if (proto_dem_params.aead_dem().type_url() ==
          "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key" ||
      // TODO: b/330508549 - Remove type URL exception for an existing key.
      proto_dem_params.aead_dem().type_url() ==
          "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305KeyFormat") {
    XChaCha20Poly1305KeyFormatTP format;
    if (!format.ParseFromString(proto_dem_params.aead_dem().value())) {
      return absl::InvalidArgumentError(
          "Failed to parse XChaCha20Poly1305Key proto");
    }
    return EciesParameters::DemId::kXChaCha20Poly1305Raw;
  }
  if (proto_dem_params.aead_dem().type_url() ==
      "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey") {
    AesCtrHmacAeadKeyFormatTP aes_ctr_hmac_aead_key_format;
    if (!aes_ctr_hmac_aead_key_format.ParseFromString(
            proto_dem_params.aead_dem().value())) {
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

ProtoEciesAeadDemParams CreateEciesAeadDemParamsStruct(
    absl::string_view type_url, const std::string& serialized_key_format) {
  ProtoEciesAeadDemParams dem_params;
  dem_params.mutable_aead_dem()->set_type_url(type_url);
  dem_params.mutable_aead_dem()->set_output_prefix_type(
      OutputPrefixTypeEnum::kTink);
  dem_params.mutable_aead_dem()->set_value(serialized_key_format);
  return dem_params;
}

absl::StatusOr<ProtoEciesAeadDemParams> ToProtoDemParams(
    EciesParameters::DemId dem_id) {
  if (dem_id == EciesParameters::DemId::kAes128GcmRaw ||
      dem_id == EciesParameters::DemId::kAes256GcmRaw) {
    int key_size = (dem_id == EciesParameters::DemId::kAes128GcmRaw) ? 16 : 32;
    AesGcmKeyFormatTP key_format;
    key_format.set_version(0);
    key_format.set_key_size(key_size);
    return CreateEciesAeadDemParamsStruct(
        "type.googleapis.com/google.crypto.tink.AesGcmKey",
        key_format.SerializeAsString());
  }
  if (dem_id == EciesParameters::DemId::kAes256SivRaw) {
    AesSivKeyFormatTP format;
    format.set_version(0);
    format.set_key_size(64);
    return CreateEciesAeadDemParamsStruct(
        "type.googleapis.com/google.crypto.tink.AesSivKey",
        format.SerializeAsString());
  }
  if (dem_id == EciesParameters::DemId::kXChaCha20Poly1305Raw) {
    XChaCha20Poly1305KeyFormatTP format;
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

    AesCtrHmacAeadKeyFormatTP format;
    format.mutable_aes_ctr_key_format()->set_key_size(key_size);
    format.mutable_aes_ctr_key_format()->mutable_params()->set_iv_size(16);
    format.mutable_hmac_key_format()->set_version(0);
    format.mutable_hmac_key_format()->set_key_size(32);
    format.mutable_hmac_key_format()->mutable_params()->set_tag_size(tag_size);
    format.mutable_hmac_key_format()->mutable_params()->set_hash(
        HashTypeEnum::kSha256);

    return CreateEciesAeadDemParamsStruct(
        "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey",
        format.SerializeAsString());
  }
  return absl::InvalidArgumentError(
      "Unable to convert DEM id to proto DEM params.");
}

absl::StatusOr<EciesParameters> ToParameters(
    OutputPrefixTypeEnum output_prefix_type,
    const ProtoEciesAeadHkdfParams& params) {
  absl::StatusOr<EciesParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<EciesParameters::CurveType> curve_type =
      FromProtoCurveType(params.kem_params().curve_type());
  if (!curve_type.ok()) {
    return curve_type.status();
  }

  absl::StatusOr<EciesParameters::HashType> hash_type =
      FromProtoHashType(params.kem_params().hkdf_hash_type());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  absl::StatusOr<EciesParameters::DemId> dem_id =
      FromProtoDemParams(params.dem_params());
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
        FromProtoPointFormat(params.ec_point_format());
    if (!point_format.ok()) {
      return point_format.status();
    }
    builder.SetNistCurvePointFormat(*point_format);
  }

  if (!params.kem_params().hkdf_salt().empty()) {
    builder.SetSalt(params.kem_params().hkdf_salt());
  }

  return builder.Build();
}

absl::StatusOr<ProtoEciesAeadHkdfParams> FromParameters(
    const EciesParameters& parameters) {
  absl::StatusOr<EllipticCurveTypeEnum> curve_type =
      ToProtoCurveType(parameters.GetCurveType());
  if (!curve_type.ok()) {
    return curve_type.status();
  }

  absl::StatusOr<HashTypeEnum> hash_type =
      ToProtoHashType(parameters.GetHashType());
  if (!hash_type.ok()) {
    return hash_type.status();
  }

  absl::StatusOr<ProtoEciesAeadDemParams> dem_params =
      ToProtoDemParams(parameters.GetDemId());
  if (!dem_params.ok()) {
    return dem_params.status();
  }

  ProtoEciesAeadHkdfParams params;
  *params.mutable_dem_params() = *dem_params;
  params.mutable_kem_params()->set_curve_type(*curve_type);
  params.mutable_kem_params()->set_hkdf_hash_type(*hash_type);
  if (parameters.GetSalt().has_value()) {
    params.mutable_kem_params()->set_hkdf_salt(*parameters.GetSalt());
  }
  if (parameters.GetNistCurvePointFormat().has_value()) {
    absl::StatusOr<EcPointFormatEnum> ec_point_format =
        ToProtoPointFormat(*parameters.GetNistCurvePointFormat());
    if (!ec_point_format.ok()) {
      return ec_point_format.status();
    }
    params.set_ec_point_format(*ec_point_format);
  } else {
    // Must be X25519, so set to the compressed format.
    params.set_ec_point_format(EcPointFormatEnum::kCompressed);
  }

  return params;
}

absl::StatusOr<EciesPublicKey> ToPublicKey(
    const EciesParameters& parameters,
    const ProtoEciesAeadHkdfPublicKey& proto_key,
    absl::optional<int> id_requirement) {
  if (IsNistCurve(parameters.GetCurveType())) {
    EcPoint point(BigInteger(proto_key.x()), BigInteger(proto_key.y()));
    return EciesPublicKey::CreateForNistCurve(parameters, point, id_requirement,
                                              GetPartialKeyAccess());
  }
  return EciesPublicKey::CreateForCurveX25519(
      parameters, proto_key.x(), id_requirement, GetPartialKeyAccess());
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

absl::StatusOr<ProtoEciesAeadHkdfPublicKey> FromPublicKey(
    const ProtoEciesAeadHkdfParams& params, const EciesPublicKey& public_key) {
  ProtoEciesAeadHkdfPublicKey proto_key;
  proto_key.set_version(0);
  *proto_key.mutable_params() = params;
  if (public_key.GetNistCurvePoint(GetPartialKeyAccess()).has_value()) {
    EcPoint point = *public_key.GetNistCurvePoint(GetPartialKeyAccess());
    absl::StatusOr<int> encoding_length =
        GetEncodingLength(public_key.GetParameters().GetCurveType());
    if (!encoding_length.ok()) {
      return encoding_length.status();
    }
    absl::StatusOr<std::string> x =
        GetValueOfFixedLength(point.GetX().GetValue(), *encoding_length);
    if (!x.ok()) {
      return x.status();
    }
    absl::StatusOr<std::string> y =
        GetValueOfFixedLength(point.GetY().GetValue(), *encoding_length);
    if (!y.ok()) {
      return y.status();
    }
    proto_key.set_x(*x);
    proto_key.set_y(*y);
  } else {
    if (!public_key.GetX25519CurvePointBytes(GetPartialKeyAccess())
             .has_value()) {
      return absl::InvalidArgumentError(
          "X25519 public key missing point bytes.");
    }
    proto_key.set_x(
        *public_key.GetX25519CurvePointBytes(GetPartialKeyAccess()));
    proto_key.set_y("");
  }
  return proto_key;
}

absl::StatusOr<EciesParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  const KeyTemplateTP& key_template = serialization.GetKeyTemplate();
  if (key_template.type_url() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing EciesParameters.");
  }

  ProtoEciesAeadHkdfKeyFormat proto_key_format;
  if (!proto_key_format.ParseFromString(key_template.value())) {
    return absl::InvalidArgumentError(
        "Failed to parse EciesAeadHkdfKeyFormat proto");
  }

  return ToParameters(key_template.output_prefix_type(),
                      proto_key_format.params());
}

absl::StatusOr<EciesPublicKey> ParsePublicKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing EciesAeadHkdfPublicKey.");
  }

  const RestrictedData& restricted_data = serialization.SerializedKeyProto();
  ProtoEciesAeadHkdfPublicKey proto_key;
  if (!proto_key.ParseFromString(
          restricted_data.GetSecret(InsecureSecretKeyAccess::Get()))) {
    return absl::InvalidArgumentError(
        "Failed to parse EciesAeadHkdfPublicKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 keys are accepted for EciesAeadHkdfPublicKey proto.");
  }

  absl::StatusOr<EciesParameters> parameters =
      ToParameters(serialization.GetOutputPrefixTypeEnum(), proto_key.params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  return ToPublicKey(*parameters, proto_key, serialization.IdRequirement());
}

absl::StatusOr<EciesPrivateKey> ParsePrivateKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing EciesAeadHkdfPrivateKey.");
  }
  ProtoEciesAeadHkdfPrivateKey proto_key;
  if (!proto_key.ParseFromString(SecretDataAsStringView(
          serialization.SerializedKeyProto().Get(*token)))) {
    return absl::InvalidArgumentError(
        "Failed to parse EciesAeadHkdfPrivateKey proto");
  }
  if (proto_key.version() != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 keys are accepted for EciesAeadHkdfPrivateKey proto.");
  }

  if (proto_key.public_key().version() != 0) {
    return absl::InvalidArgumentError(
        "Only version 0 public keys are accepted for "
        "EciesAeadHkdfPrivateKey proto.");
  }

  const OutputPrefixTypeEnum output_prefix_type =
      serialization.GetOutputPrefixTypeEnum();

  absl::StatusOr<EciesParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<EciesParameters> parameters =
      ToParameters(output_prefix_type, proto_key.public_key().params());
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<EciesPublicKey> public_key = ToPublicKey(
      *parameters, proto_key.public_key(), serialization.IdRequirement());
  if (!public_key.ok()) {
    return public_key.status();
  }

  if (IsNistCurve(parameters->GetCurveType())) {
    return EciesPrivateKey::CreateForNistCurve(
        *public_key, RestrictedBigInteger(proto_key.key_value(), *token),
        GetPartialKeyAccess());
  }

  return EciesPrivateKey::CreateForCurveX25519(
      *public_key, RestrictedData(proto_key.key_value(), *token),
      GetPartialKeyAccess());
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const EciesParameters& parameters) {
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<ProtoEciesAeadHkdfParams> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }
  ProtoEciesAeadHkdfKeyFormat proto_key_format;
  *proto_key_format.mutable_params() = *params;

  return ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type,
      proto_key_format.SerializeAsString());
}

absl::StatusOr<ProtoKeySerialization> SerializePublicKey(
    const EciesPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<ProtoEciesAeadHkdfParams> params =
      FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  absl::StatusOr<ProtoEciesAeadHkdfPublicKey> proto_key =
      FromPublicKey(*params, key);
  if (!proto_key.ok()) {
    return proto_key.status();
  }

  absl::StatusOr<std::string> serialized_proto_key =
      proto_key->SerializeAsString();
  if (!serialized_proto_key.ok()) {
    return serialized_proto_key.status();
  }
  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output =
      RestrictedData(*serialized_proto_key, InsecureSecretKeyAccess::Get());
  return ProtoKeySerialization::Create(
      kPublicTypeUrl, restricted_output, KeyMaterialTypeEnum::kAsymmetricPublic,
      *output_prefix_type, key.GetIdRequirement());
}

absl::StatusOr<ProtoKeySerialization> SerializePrivateKey(
    const EciesPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  absl::StatusOr<ProtoEciesAeadHkdfParams> params =
      FromParameters(key.GetPublicKey().GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  absl::StatusOr<ProtoEciesAeadHkdfPublicKey> proto_public_key =
      FromPublicKey(*params, key.GetPublicKey());
  if (!proto_public_key.ok()) {
    return proto_public_key.status();
  }

  ProtoEciesAeadHkdfPrivateKey proto_private_key;
  proto_private_key.set_version(0);
  *proto_private_key.mutable_public_key() = *proto_public_key;
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
    absl::StatusOr<SecretData> key_value = GetSecretValueOfFixedLength(
        *secret, *encoding_length, InsecureSecretKeyAccess::Get());
    if (!key_value.ok()) {
      return key_value.status();
    }
    proto_private_key.set_key_value(*key_value);
  } else {
    absl::optional<RestrictedData> secret =
        key.GetX25519PrivateKeyBytes(GetPartialKeyAccess());
    if (!secret.has_value()) {
      return absl::InternalError(
          "X25519 private key is missing X25519 private key bytes.");
    }
    proto_private_key.set_key_value(
        secret->Get(InsecureSecretKeyAccess::Get()));
  }

  absl::StatusOr<OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<SecretData> serialized_proto_private_key =
      proto_private_key.SerializeAsSecretData();
  if (!serialized_proto_private_key.ok()) {
    return serialized_proto_private_key.status();
  }
  RestrictedData restricted_output =
      RestrictedData(*serialized_proto_private_key, *token);
  return ProtoKeySerialization::Create(kPrivateTypeUrl, restricted_output,
                                       KeyMaterialTypeEnum::kAsymmetricPrivate,
                                       *output_prefix_type,
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

absl::Status RegisterEciesProtoSerializationWithMutableRegistry(
    MutableSerializationRegistry& registry) {
  absl::Status status =
      registry.RegisterParametersParser(EciesProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      registry.RegisterParametersSerializer(EciesProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(EciesProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeySerializer(EciesProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = registry.RegisterKeyParser(EciesProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return registry.RegisterKeySerializer(EciesProtoPrivateKeySerializer());
}

absl::Status RegisterEciesProtoSerializationWithRegistryBuilder(
    SerializationRegistry::Builder& builder) {
  absl::Status status =
      builder.RegisterParametersParser(EciesProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status =
      builder.RegisterParametersSerializer(EciesProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(EciesProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeySerializer(EciesProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = builder.RegisterKeyParser(EciesProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return builder.RegisterKeySerializer(EciesProtoPrivateKeySerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
