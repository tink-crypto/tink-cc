// Copyright 2026 Google LLC
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

#include "tink/hybrid/internal/ecies_aead_hkdf_hybrid_decrypt.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/daead/deterministic_aead_key_templates.h"
#include "tink/daead/subtle/aead_or_daead.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_private_key.h"
#include "tink/hybrid/internal/ecies_aead_hkdf_dem_helper.h"
#include "tink/hybrid_decrypt.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/ecies_hkdf_recipient_kem_boringssl.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

absl::StatusOr<subtle::EllipticCurveType> ToSubtleCurve(
    EciesParameters::CurveType curve_type) {
  switch (curve_type) {
    case EciesParameters::CurveType::kNistP256:
      return subtle::EllipticCurveType::NIST_P256;
    case EciesParameters::CurveType::kNistP384:
      return subtle::EllipticCurveType::NIST_P384;
    case EciesParameters::CurveType::kNistP521:
      return subtle::EllipticCurveType::NIST_P521;
    case EciesParameters::CurveType::kX25519:
      return subtle::EllipticCurveType::CURVE25519;
    default:
      return absl::InvalidArgumentError("Unsupported elliptic curve");
  }
}

absl::StatusOr<subtle::HashType> ToSubtleHash(
    EciesParameters::HashType hash_type) {
  switch (hash_type) {
    case EciesParameters::HashType::kSha1:
      return subtle::HashType::SHA1;
    case EciesParameters::HashType::kSha224:
      return subtle::HashType::SHA224;
    case EciesParameters::HashType::kSha256:
      return subtle::HashType::SHA256;
    case EciesParameters::HashType::kSha384:
      return subtle::HashType::SHA384;
    case EciesParameters::HashType::kSha512:
      return subtle::HashType::SHA512;
    default:
      return absl::InvalidArgumentError("Unsupported hash type");
  }
}

absl::StatusOr<subtle::EcPointFormat> ToSubtlePointFormat(
    const EciesParameters& parameters) {
  if (parameters.GetCurveType() == EciesParameters::CurveType::kX25519) {
    return subtle::EcPointFormat::COMPRESSED;
  }
  std::optional<EciesParameters::PointFormat> point_format =
      parameters.GetNistCurvePointFormat();
  if (!point_format.has_value()) {
    return absl::InvalidArgumentError("Missing point format for NIST curve");
  }
  switch (*point_format) {
    case EciesParameters::PointFormat::kCompressed:
      return subtle::EcPointFormat::COMPRESSED;
    case EciesParameters::PointFormat::kUncompressed:
      return subtle::EcPointFormat::UNCOMPRESSED;
    case EciesParameters::PointFormat::kLegacyUncompressed:
      return subtle::EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED;
    default:
      return absl::InvalidArgumentError("Unsupported EC point format");
  }
}

absl::StatusOr<google::crypto::tink::KeyTemplate> ToDemKeyTemplate(
    EciesParameters::DemId dem_id) {
  switch (dem_id) {
    case EciesParameters::DemId::kAes128GcmRaw:
      return AeadKeyTemplates::Aes128GcmNoPrefix();
    case EciesParameters::DemId::kAes256GcmRaw:
      return AeadKeyTemplates::Aes256GcmNoPrefix();
    case EciesParameters::DemId::kAes256SivRaw:
      return DeterministicAeadKeyTemplates::Aes256Siv();
    case EciesParameters::DemId::kXChaCha20Poly1305Raw:
      return AeadKeyTemplates::XChaCha20Poly1305();
    case EciesParameters::DemId::kAes128CtrHmacSha256Raw:
      return AeadKeyTemplates::Aes128CtrHmacSha256();
    case EciesParameters::DemId::kAes256CtrHmacSha256Raw:
      return AeadKeyTemplates::Aes256CtrHmacSha256();
    default:
      return absl::InvalidArgumentError("Unsupported DEM");
  }
}

class EciesAeadHkdfHybridDecryptImpl : public HybridDecrypt {
 public:
  EciesAeadHkdfHybridDecryptImpl(
      std::unique_ptr<const subtle::EciesHkdfRecipientKemBoringSsl>
          recipient_kem,
      std::unique_ptr<const EciesAeadHkdfDemHelper> dem_helper,
      subtle::HashType hkdf_hash, subtle::EcPointFormat point_format,
      size_t encapsulated_key_size, absl::string_view hkdf_salt,
      absl::string_view output_prefix)
      : recipient_kem_(std::move(recipient_kem)),
        dem_helper_(std::move(dem_helper)),
        hkdf_hash_(hkdf_hash),
        point_format_(point_format),
        encapsulated_key_size_(encapsulated_key_size),
        hkdf_salt_(hkdf_salt),
        output_prefix_(output_prefix) {}

  absl::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view context_info) const override {
    if (!absl::StartsWith(ciphertext, output_prefix_)) {
      return absl::InvalidArgumentError("OutputPrefix does not match");
    }
    absl::string_view raw_ciphertext =
        absl::StripPrefix(ciphertext, output_prefix_);
    if (raw_ciphertext.size() < encapsulated_key_size_) {
      return absl::InvalidArgumentError("ciphertext too short");
    }

    // Use KEM to get a symmetric key.
    ABSL_ASSIGN_OR_RETURN(
        SecretData symmetric_key,
        recipient_kem_->GenerateKey(
            raw_ciphertext.substr(0, encapsulated_key_size_), hkdf_hash_,
            hkdf_salt_, context_info, dem_helper_->dem_key_size_in_bytes(),
            point_format_));

    // Use the symmetric key to get an AEAD-primitive.
    ABSL_ASSIGN_OR_RETURN(std::unique_ptr<subtle::AeadOrDaead> aead_or_daead,
                          dem_helper_->GetAeadOrDaead(symmetric_key));

    // Do the actual decryption using the AEAD-primitive.
    return aead_or_daead->Decrypt(raw_ciphertext.substr(encapsulated_key_size_),
                                  "");  // empty aad
  }

 private:
  std::unique_ptr<const subtle::EciesHkdfRecipientKemBoringSsl> recipient_kem_;
  std::unique_ptr<const EciesAeadHkdfDemHelper> dem_helper_;
  subtle::HashType hkdf_hash_;
  subtle::EcPointFormat point_format_;
  size_t encapsulated_key_size_;
  std::string hkdf_salt_;
  std::string output_prefix_;
};

}  // namespace

absl::StatusOr<std::unique_ptr<HybridDecrypt>> NewEciesAeadHkdfHybridDecrypt(
    const EciesPrivateKey& recipient_key) {
  const EciesParameters& parameters =
      recipient_key.GetPublicKey().GetParameters();
  ABSL_ASSIGN_OR_RETURN(subtle::EllipticCurveType curve,
                        ToSubtleCurve(parameters.GetCurveType()));
  ABSL_ASSIGN_OR_RETURN(subtle::HashType hkdf_hash,
                        ToSubtleHash(parameters.GetHashType()));
  ABSL_ASSIGN_OR_RETURN(subtle::EcPointFormat point_format,
                        ToSubtlePointFormat(parameters));
  ABSL_ASSIGN_OR_RETURN(google::crypto::tink::KeyTemplate dem_key_template,
                        ToDemKeyTemplate(parameters.GetDemId()));

  ABSL_ASSIGN_OR_RETURN(int32_t encapsulated_key_size_result,
                        EcPointEncodingSizeInBytes(curve, point_format));
  ABSL_CHECK_GE(encapsulated_key_size_result, 0);
  size_t encapsulated_key_size =
      static_cast<size_t>(encapsulated_key_size_result);

  std::optional<RestrictedData> private_key_bytes =
      (parameters.GetCurveType() == EciesParameters::CurveType::kX25519)
          ? recipient_key.GetX25519PrivateKeyBytes(GetPartialKeyAccess())
          : recipient_key.GetNistPrivateKeyBytes(GetPartialKeyAccess());
  if (!private_key_bytes.has_value()) {
    return absl::InvalidArgumentError("Missing private key bytes.");
  }

  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<const subtle::EciesHkdfRecipientKemBoringSsl>
          recipient_kem,
      subtle::EciesHkdfRecipientKemBoringSsl::New(
          curve, private_key_bytes->Get(InsecureSecretKeyAccess::Get())));
  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<const EciesAeadHkdfDemHelper> dem_helper,
      EciesAeadHkdfDemHelper::New(dem_key_template));

  return std::make_unique<EciesAeadHkdfHybridDecryptImpl>(
      std::move(recipient_kem), std::move(dem_helper), hkdf_hash, point_format,
      encapsulated_key_size, parameters.GetSalt().value_or(""),
      recipient_key.GetOutputPrefix());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
