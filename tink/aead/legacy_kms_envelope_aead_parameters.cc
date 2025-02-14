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

#include "tink/aead/legacy_kms_envelope_aead_parameters.h"

#include <memory>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/aead/aead_parameters.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

absl::Status ValidateDekParsingStrategy(
    LegacyKmsEnvelopeAeadParameters::DekParsingStrategy dek_parsing_strategy,
    const AeadParameters& dek_parameters) {
  if (dek_parsing_strategy == LegacyKmsEnvelopeAeadParameters::
                                  DekParsingStrategy::kAssumeAesCtrHmac &&
      typeid(dek_parameters) == typeid(AesCtrHmacAeadParameters)) {
    return absl::OkStatus();
  }
  if (dek_parsing_strategy ==
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesEax &&
      typeid(dek_parameters) == typeid(AesEaxParameters)) {
    return absl::OkStatus();
  }
  if (dek_parsing_strategy ==
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesGcm &&
      typeid(dek_parameters) == typeid(AesGcmParameters)) {
    return absl::OkStatus();
  }
  if (dek_parsing_strategy == LegacyKmsEnvelopeAeadParameters::
                                  DekParsingStrategy::kAssumeAesGcmSiv &&
      typeid(dek_parameters) == typeid(AesGcmSivParameters)) {
    return absl::OkStatus();
  }
  if (dek_parsing_strategy ==
          LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
              kAssumeXChaCha20Poly1305 &&
      typeid(dek_parameters) == typeid(XChaCha20Poly1305Parameters)) {
    return absl::OkStatus();
  }
  return absl::Status(absl::StatusCode::kInvalidArgument,
                      "Cannot create legacy KMS Envelope AEAD parameters with "
                      "mismatching parsing strategy and DEK parameters type.");
}

}  // namespace

absl::StatusOr<LegacyKmsEnvelopeAeadParameters>
LegacyKmsEnvelopeAeadParameters::Create(absl::string_view key_uri,
                                        Variant variant,
                                        DekParsingStrategy dek_parsing_strategy,
                                        const AeadParameters& dek_parameters) {
  if (variant != Variant::kTink && variant != Variant::kNoPrefix) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot create legacy KMS Envelope AEAD parameters "
                        "with unknown variant.");
  }
  if (dek_parameters.HasIdRequirement()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "DEK parameters must not have an ID requirement.");
  }
  absl::Status status =
      ValidateDekParsingStrategy(dek_parsing_strategy, dek_parameters);
  if (!status.ok()) {
    return status;
  }

  std::unique_ptr<Parameters> cloned_dek_parameters = dek_parameters.Clone();
  const AeadParameters* dek_parameters_ptr =
      dynamic_cast<const AeadParameters*>(cloned_dek_parameters.get());
  if (dek_parameters_ptr == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "DEK parameters cannot be set to non-AEAD parameters.");
  }

  return LegacyKmsEnvelopeAeadParameters(
      key_uri, variant, dek_parsing_strategy,
      absl::WrapUnique(dynamic_cast<const AeadParameters*>(
          cloned_dek_parameters.release())));
}

bool LegacyKmsEnvelopeAeadParameters::operator==(
    const Parameters& other) const {
  const LegacyKmsEnvelopeAeadParameters* that =
      dynamic_cast<const LegacyKmsEnvelopeAeadParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  return key_uri_ == that->key_uri_ && variant_ == that->variant_ &&
         dek_parsing_strategy_ == that->dek_parsing_strategy_ &&
         *dek_parameters_ == *that->dek_parameters_;
}

}  // namespace tink
}  // namespace crypto
