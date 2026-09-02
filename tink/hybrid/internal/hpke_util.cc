// Copyright 2022 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

#include "tink/hybrid/internal/hpke_util.h"

#include <cstdint>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/output_prefix_util.h"
#include "tink/subtle/common_enums.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

// Encapsulated key length for XWing, see
// https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-09.
constexpr int kXWingEncapsulatedKeyLength = 1120;
// Encapsulated key length for ML-KEM-768, see
// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-01.
constexpr int kMlKem768EncapsulatedKeyLength = 1088;
// Encapsulated key length for ML-KEM-1024, see
// https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-01.
constexpr int kMlKem1024EncapsulatedKeyLength = 1568;

absl::StatusOr<HpkeKem> HpkeKemProtoToEnum(google::crypto::tink::HpkeKem kem) {
  switch (kem) {
    case google::crypto::tink::HpkeKem::DHKEM_X25519_HKDF_SHA256:
      return HpkeKem::kX25519HkdfSha256;
    case google::crypto::tink::HpkeKem::DHKEM_P256_HKDF_SHA256:
      return HpkeKem::kP256HkdfSha256;
    case google::crypto::tink::HpkeKem::X_WING:
      return HpkeKem::kXWing;
    case google::crypto::tink::HpkeKem::ML_KEM768:
      return HpkeKem::kMlKem768;
    case google::crypto::tink::HpkeKem::ML_KEM1024:
      return HpkeKem::kMlKem1024;
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unable to convert unsupported HPKE KEM: ", kem));
  }
}

absl::StatusOr<HpkeKdf> HpkeKdfProtoToEnum(google::crypto::tink::HpkeKdf kdf) {
  switch (kdf) {
    case google::crypto::tink::HpkeKdf::HKDF_SHA256:
      return HpkeKdf::kHkdfSha256;
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unable to convert unsupported HPKE KDF: ", kdf));
  }
}

absl::StatusOr<HpkeAead> HpkeAeadProtoToEnum(
    google::crypto::tink::HpkeAead aead) {
  switch (aead) {
    case google::crypto::tink::HpkeAead::AES_128_GCM:
      return HpkeAead::kAes128Gcm;
    case google::crypto::tink::HpkeAead::AES_256_GCM:
      return HpkeAead::kAes256Gcm;
    case google::crypto::tink::HpkeAead::CHACHA20_POLY1305:
      return HpkeAead::kChaCha20Poly1305;
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unable to convert unsupported HPKE AEAD: ", aead));
  }
}

constexpr int kAeadTagLength = 16;

absl::StatusOr<int32_t> AeadTagLength(HpkeParameters::AeadId aead_id) {
  switch (aead_id) {
    case HpkeParameters::AeadId::kAesGcm128:
    case HpkeParameters::AeadId::kAesGcm256:
    case HpkeParameters::AeadId::kChaCha20Poly1305:
      return kAeadTagLength;
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unable to determine AEAD tag length for ", aead_id));
  }
}

absl::StatusOr<int32_t> OutputPrefixLength(HpkeParameters::Variant variant) {
  switch (variant) {
    case HpkeParameters::Variant::kNoPrefix:
      return 0;
    case HpkeParameters::Variant::kTink:
    case HpkeParameters::Variant::kCrunchy:
      return internal::kOutputPrefixSize;
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unable to determine output prefix length for ",
                       variant));
  }
}

}  // namespace

absl::StatusOr<HpkeParams> HpkeParamsProtoToStruct(
    google::crypto::tink::HpkeParams params) {
  absl::StatusOr<HpkeKem> kem = HpkeKemProtoToEnum(params.kem());
  if (!kem.ok()) return kem.status();
  absl::StatusOr<HpkeKdf> kdf = HpkeKdfProtoToEnum(params.kdf());
  if (!kdf.ok()) return kdf.status();
  absl::StatusOr<HpkeAead> aead = HpkeAeadProtoToEnum(params.aead());
  if (!aead.ok()) return aead.status();
  return HpkeParams{*kem, *kdf, *aead};
}

absl::StatusOr<int32_t> HpkeEncapsulatedKeyLength(
    google::crypto::tink::HpkeKem kem) {
  switch (kem) {
    case google::crypto::tink::HpkeKem::DHKEM_X25519_HKDF_SHA256:
      return internal::EcPointEncodingSizeInBytes(
          subtle::EllipticCurveType::CURVE25519,
          subtle::EcPointFormat::UNCOMPRESSED);
    case google::crypto::tink::HpkeKem::DHKEM_P256_HKDF_SHA256:
      return internal::EcPointEncodingSizeInBytes(
          subtle::EllipticCurveType::NIST_P256,
          subtle::EcPointFormat::UNCOMPRESSED);
    case google::crypto::tink::HpkeKem::X_WING:
      return kXWingEncapsulatedKeyLength;
    case google::crypto::tink::HpkeKem::ML_KEM768:
      return kMlKem768EncapsulatedKeyLength;
    case google::crypto::tink::HpkeKem::ML_KEM1024:
      return kMlKem1024EncapsulatedKeyLength;
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unable to determine KEM-encoding length for ", kem));
  }
}

absl::StatusOr<int32_t> HpkeEncapsulatedKeyLength(
    HpkeParameters::KemId kem_id) {
  switch (kem_id) {
    case HpkeParameters::KemId::kDhkemX25519HkdfSha256:
      return internal::EcPointEncodingSizeInBytes(
          subtle::EllipticCurveType::CURVE25519,
          subtle::EcPointFormat::UNCOMPRESSED);
    case HpkeParameters::KemId::kDhkemP256HkdfSha256:
      return internal::EcPointEncodingSizeInBytes(
          subtle::EllipticCurveType::NIST_P256,
          subtle::EcPointFormat::UNCOMPRESSED);
    case HpkeParameters::KemId::kXWing:
      return kXWingEncapsulatedKeyLength;
    case HpkeParameters::KemId::kMlKem768:
      return kMlKem768EncapsulatedKeyLength;
    case HpkeParameters::KemId::kMlKem1024:
      return kMlKem1024EncapsulatedKeyLength;
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unable to determine KEM-encoding length for ", kem_id));
  }
}

absl::StatusOr<int32_t> GetEncryptionOverhead(const HpkeParameters& params) {
  absl::StatusOr<int32_t> kem_length =
      HpkeEncapsulatedKeyLength(params.GetKemId());
  if (!kem_length.ok()) {
    return kem_length.status();
  }
  absl::StatusOr<int32_t> aead_overhead = AeadTagLength(params.GetAeadId());
  if (!aead_overhead.ok()) {
    return aead_overhead.status();
  }
  absl::StatusOr<int32_t> output_prefix_size =
      OutputPrefixLength(params.GetVariant());
  if (!output_prefix_size.ok()) {
    return output_prefix_size.status();
  }
  return *kem_length + *aead_overhead + *output_prefix_size;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
