// Copyright 2024 Google LLC
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

#include "tink/keyderivation/prf_based_key_derivation_key.h"

#include <memory>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/key.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"
#include "tink/parameters.h"
#include "tink/partial_key_access_token.h"
#include "tink/prf/prf_key.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<PrfBasedKeyDerivationKey> PrfBasedKeyDerivationKey::Create(
    const PrfBasedKeyDerivationParameters& parameters, const PrfKey& prf_key,
    absl::optional<int> id_requirement, PartialKeyAccessToken token) {
  if (parameters.GetPrfParameters() != prf_key.GetParameters()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "PrfParameters for `parameters` and `prf_key` must match.");
  }
  if (parameters.GetDerivedKeyParameters().HasIdRequirement() &&
      !id_requirement.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot create key without ID requirement with derived "
                        "key parameters with ID requirement");
  }
  if (!parameters.GetDerivedKeyParameters().HasIdRequirement() &&
      id_requirement.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot create key with ID requirement with derived "
                        "key parameters without ID requirement");
  }

  std::unique_ptr<Parameters> cloned_parameters = parameters.Clone();
  const PrfBasedKeyDerivationParameters* parameters_ptr =
      dynamic_cast<const PrfBasedKeyDerivationParameters*>(
          cloned_parameters.get());
  if (parameters_ptr == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Unable to clone PRF-based key derivation parameters.");
  }

  std::unique_ptr<Key> cloned_prf_key = prf_key.Clone();
  const PrfKey* prf_key_ptr = dynamic_cast<const PrfKey*>(cloned_prf_key.get());
  if (prf_key_ptr == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Unable to clone PRF key.");
  }

  return PrfBasedKeyDerivationKey(
      absl::WrapUnique(dynamic_cast<const PrfBasedKeyDerivationParameters*>(
          cloned_parameters.release())),
      absl::WrapUnique(dynamic_cast<const PrfKey*>(cloned_prf_key.release())),
      id_requirement);
}

bool PrfBasedKeyDerivationKey::operator==(const Key& other) const {
  const PrfBasedKeyDerivationKey* that =
      dynamic_cast<const PrfBasedKeyDerivationKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (GetParameters() != that->GetParameters()) {
    return false;
  }
  if (*prf_key_ != *that->prf_key_) {
    return false;
  }
  if (id_requirement_ != that->id_requirement_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
