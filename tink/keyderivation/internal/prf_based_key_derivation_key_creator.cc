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
////////////////////////////////////////////////////////////////////////////////

#include "tink/keyderivation/internal/prf_based_key_derivation_key_creator.h"

#include <memory>
#include <optional>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/key.h"
#include "tink/keyderivation/prf_based_key_derivation_key.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/rtti.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<Key>> CreatePrfBasedKeyDerivationKey(
    const PrfBasedKeyDerivationParameters& parameters,
    std::optional<int> id_requirement) {
  const auto* hkdf_prf_parameters =
      DynamicCast<const HkdfPrfParameters*>(&parameters.GetPrfParameters());
  if (hkdf_prf_parameters == nullptr) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create PrfBasedKeyDerivationKey: only HkdfPrfParameters is "
        "supported.");
  }
  RestrictedData prf_key_bytes(hkdf_prf_parameters->KeySizeInBytes());
  ABSL_ASSIGN_OR_RETURN(HkdfPrfKey prf_key,
                        HkdfPrfKey::Create(*hkdf_prf_parameters, prf_key_bytes,
                                           GetPartialKeyAccess()));
  ABSL_ASSIGN_OR_RETURN(
      PrfBasedKeyDerivationKey key,
      PrfBasedKeyDerivationKey::Create(parameters, prf_key, id_requirement,
                                       GetPartialKeyAccess()));
  return std::make_unique<PrfBasedKeyDerivationKey>(std::move(key));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
