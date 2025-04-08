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

#include "tink/experimental/pqcrypto/kem/cecpq2_parameters.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/parameters.h"

namespace crypto {
namespace tink {
namespace {

template <typename T>
absl::Status ValidateNoPrefix(T dem_variant) {
  if (dem_variant != T::kNoPrefix) {
    return absl::InvalidArgumentError("DEM requires no-prefix variant.");
  }
  return absl::OkStatus();
}

absl::Status ValidateDemParameters(const Parameters& parameters) {
  if (typeid(parameters) == typeid(AesGcmParameters)) {
    const AesGcmParameters* aes_gcm_parameters =
        dynamic_cast<const AesGcmParameters*>(&parameters);
    if (aes_gcm_parameters == nullptr) {
      return absl::InternalError("Failed to cast AesGcmParameters.");
    }
    return ValidateNoPrefix<AesGcmParameters::Variant>(
        aes_gcm_parameters->GetVariant());
  }
  if (typeid(parameters) == typeid(XChaCha20Poly1305Parameters)) {
    const XChaCha20Poly1305Parameters* xchacha20_poly1305_parameters =
        dynamic_cast<const XChaCha20Poly1305Parameters*>(&parameters);
    if (xchacha20_poly1305_parameters == nullptr) {
      return absl::InternalError("Failed to cast XChaCha20Poly1305Parameters.");
    }
    return ValidateNoPrefix<XChaCha20Poly1305Parameters::Variant>(
        xchacha20_poly1305_parameters->GetVariant());
  }
  if (typeid(parameters) == typeid(AesSivParameters)) {
    const AesSivParameters* aes_siv_parameters =
        dynamic_cast<const AesSivParameters*>(&parameters);
    if (aes_siv_parameters == nullptr) {
      return absl::InternalError("Failed to cast AesSivParameters.");
    }
    return ValidateNoPrefix<AesSivParameters::Variant>(
        aes_siv_parameters->GetVariant());
  }
  return absl::InvalidArgumentError(
      "DEM parameters must be AES-GCM, XChaCha20-Poly1305, or AES-SIV.");
}

}  // namespace

absl::StatusOr<Cecpq2Parameters> Cecpq2Parameters::Create(
    const Parameters& dem_parameters, absl::optional<absl::string_view> salt,
    Variant variant) {
  if (variant != Variant::kTink && variant != Variant::kNoPrefix) {
    return absl::InvalidArgumentError(
        "Cannot create CECPQ2 parameters with unknown variant.");
  }

  absl::Status valid_dem_parameters = ValidateDemParameters(dem_parameters);
  if (!valid_dem_parameters.ok()) {
    return valid_dem_parameters;
  }

  return Cecpq2Parameters(dem_parameters.Clone(), salt, variant);
}

bool Cecpq2Parameters::operator==(const Parameters& other) const {
  const Cecpq2Parameters* that = dynamic_cast<const Cecpq2Parameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (salt_ != that->salt_) {
    return false;
  }
  if (variant_ != that->variant_) {
    return false;
  }
  if (*dem_parameters_ != *that->dem_parameters_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
