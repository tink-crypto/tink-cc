// Copyright 2026 Google LLC
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

#include "tink/hybrid/internal/hpke_proto_structs.h"

#include "absl/base/macros.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/hybrid/hpke_parameters.h"
#include "proto/hpke.tinkpb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::google::crypto::tink::internal::HpkeAeadTP;
using ::google::crypto::tink::internal::HpkeKdfTP;
using ::google::crypto::tink::internal::HpkeKemTP;
using ::google::crypto::tink::internal::HpkeParamsTP;

absl::StatusOr<HpkeParameters::Variant> ToVariant(
    google::crypto::tink::internal::OutputPrefixTypeTP output_prefix_type) {
  switch (output_prefix_type) {
    case google::crypto::tink::internal::OutputPrefixTypeTP::kLegacy:
      ABSL_FALLTHROUGH_INTENDED;  // Parse LEGACY output prefix as CRUNCHY.
    case google::crypto::tink::internal::OutputPrefixTypeTP::kCrunchy:
      return HpkeParameters::Variant::kCrunchy;
    case google::crypto::tink::internal::OutputPrefixTypeTP::kRaw:
      return HpkeParameters::Variant::kNoPrefix;
    case google::crypto::tink::internal::OutputPrefixTypeTP::kTink:
      return HpkeParameters::Variant::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine HpkeParameters::Variant");
  }
}

absl::StatusOr<HpkeParameters::KemId> ToKemId(HpkeKemTP kem) {
  switch (kem) {
    case HpkeKemTP::kDhkemP256HkdfSha256:
      return HpkeParameters::KemId::kDhkemP256HkdfSha256;
    case HpkeKemTP::kDhkemP384HkdfSha384:
      return HpkeParameters::KemId::kDhkemP384HkdfSha384;
    case HpkeKemTP::kDhkemP521HkdfSha512:
      return HpkeParameters::KemId::kDhkemP521HkdfSha512;
    case HpkeKemTP::kDhkemX25519HkdfSha256:
      return HpkeParameters::KemId::kDhkemX25519HkdfSha256;
    case HpkeKemTP::kXWing:
      return HpkeParameters::KemId::kXWing;
    case HpkeKemTP::kMlKem768:
      return HpkeParameters::KemId::kMlKem768;
    case HpkeKemTP::kMlKem1024:
      return HpkeParameters::KemId::kMlKem1024;
    default:
      return absl::InvalidArgumentError("Could not determine KEM.");
  }
}

absl::StatusOr<HpkeKemTP> FromKemId(HpkeParameters::KemId kem_id) {
  switch (kem_id) {
    case HpkeParameters::KemId::kDhkemP256HkdfSha256:
      return HpkeKemTP::kDhkemP256HkdfSha256;
    case HpkeParameters::KemId::kDhkemP384HkdfSha384:
      return HpkeKemTP::kDhkemP384HkdfSha384;
    case HpkeParameters::KemId::kDhkemP521HkdfSha512:
      return HpkeKemTP::kDhkemP521HkdfSha512;
    case HpkeParameters::KemId::kDhkemX25519HkdfSha256:
      return HpkeKemTP::kDhkemX25519HkdfSha256;
    case HpkeParameters::KemId::kXWing:
      return HpkeKemTP::kXWing;
    case HpkeParameters::KemId::kMlKem768:
      return HpkeKemTP::kMlKem768;
    case HpkeParameters::KemId::kMlKem1024:
      return HpkeKemTP::kMlKem1024;
    default:
      return absl::InvalidArgumentError("Could not determine KEM.");
  }
}

absl::StatusOr<HpkeParameters::KdfId> ToKdfId(HpkeKdfTP kdf) {
  switch (kdf) {
    case HpkeKdfTP::kHkdfSha256:
      return HpkeParameters::KdfId::kHkdfSha256;
    case HpkeKdfTP::kHkdfSha384:
      return HpkeParameters::KdfId::kHkdfSha384;
    case HpkeKdfTP::kHkdfSha512:
      return HpkeParameters::KdfId::kHkdfSha512;
    default:
      return absl::InvalidArgumentError("Could not determine KDF.");
  }
}

absl::StatusOr<HpkeKdfTP> FromKdfId(HpkeParameters::KdfId kdf_id) {
  switch (kdf_id) {
    case HpkeParameters::KdfId::kHkdfSha256:
      return HpkeKdfTP::kHkdfSha256;
    case HpkeParameters::KdfId::kHkdfSha384:
      return HpkeKdfTP::kHkdfSha384;
    case HpkeParameters::KdfId::kHkdfSha512:
      return HpkeKdfTP::kHkdfSha512;
    default:
      return absl::InvalidArgumentError("Could not determine KDF.");
  }
}

absl::StatusOr<HpkeParameters::AeadId> ToAeadId(HpkeAeadTP aead) {
  switch (aead) {
    case HpkeAeadTP::kAes128Gcm:
      return HpkeParameters::AeadId::kAesGcm128;
    case HpkeAeadTP::kAes256Gcm:
      return HpkeParameters::AeadId::kAesGcm256;
    case HpkeAeadTP::kChacha20Poly1305:
      return HpkeParameters::AeadId::kChaCha20Poly1305;
    default:
      return absl::InvalidArgumentError("Could not determine AEAD.");
  }
}

absl::StatusOr<HpkeAeadTP> FromAeadId(HpkeParameters::AeadId aead_id) {
  switch (aead_id) {
    case HpkeParameters::AeadId::kAesGcm128:
      return HpkeAeadTP::kAes128Gcm;
    case HpkeParameters::AeadId::kAesGcm256:
      return HpkeAeadTP::kAes256Gcm;
    case HpkeParameters::AeadId::kChaCha20Poly1305:
      return HpkeAeadTP::kChacha20Poly1305;
    default:
      return absl::InvalidArgumentError("Could not determine AEAD.");
  }
}

}  // namespace

absl::StatusOr<HpkeParameters> HpkeParametersFromProto(
    google::crypto::tink::internal::OutputPrefixTypeTP output_prefix_type,
    const HpkeParamsTP& params) {
  absl::StatusOr<HpkeParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<HpkeParameters::KemId> kem_id = ToKemId(params.kem());
  if (!kem_id.ok()) {
    return kem_id.status();
  }

  absl::StatusOr<HpkeParameters::KdfId> kdf_id = ToKdfId(params.kdf());
  if (!kdf_id.ok()) {
    return kdf_id.status();
  }

  absl::StatusOr<HpkeParameters::AeadId> aead_id = ToAeadId(params.aead());
  if (!aead_id.ok()) {
    return aead_id.status();
  }

  return HpkeParameters::Builder()
      .SetVariant(*variant)
      .SetKemId(*kem_id)
      .SetKdfId(*kdf_id)
      .SetAeadId(*aead_id)
      .Build();
}

absl::StatusOr<HpkeParamsTP> HpkeParamsToProto(
    const HpkeParameters& parameters) {
  absl::StatusOr<HpkeKemTP> kem = FromKemId(parameters.GetKemId());
  if (!kem.ok()) {
    return kem.status();
  }

  absl::StatusOr<HpkeKdfTP> kdf = FromKdfId(parameters.GetKdfId());
  if (!kdf.ok()) {
    return kdf.status();
  }

  absl::StatusOr<HpkeAeadTP> aead = FromAeadId(parameters.GetAeadId());
  if (!aead.ok()) {
    return aead.status();
  }

  HpkeParamsTP params;
  params.set_kem(*kem);
  params.set_kdf(*kdf);
  params.set_aead(*aead);
  return params;
}

absl::StatusOr<google::crypto::tink::internal::OutputPrefixTypeTP>
HpkeVariantToOutputPrefixType(HpkeParameters::Variant variant) {
  switch (variant) {
    case HpkeParameters::Variant::kCrunchy:
      return google::crypto::tink::internal::OutputPrefixTypeTP::kCrunchy;
    case HpkeParameters::Variant::kNoPrefix:
      return google::crypto::tink::internal::OutputPrefixTypeTP::kRaw;
    case HpkeParameters::Variant::kTink:
      return google::crypto::tink::internal::OutputPrefixTypeTP::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type.");
  }
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
