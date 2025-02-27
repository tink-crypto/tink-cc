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

#include "tink/keyderivation/prf_based_key_derivation_parameters.h"

#include <memory>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/parameters.h"
#include "tink/prf/prf_parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

PrfBasedKeyDerivationParameters::Builder&
PrfBasedKeyDerivationParameters::Builder::SetPrfParameters(
    const PrfParameters& prf_parameters) {
  prf_parameters_ = prf_parameters.Clone();
  return *this;
}

PrfBasedKeyDerivationParameters::Builder&
PrfBasedKeyDerivationParameters::Builder::SetDerivedKeyParameters(
    const Parameters& derived_key_parameters) {
  derived_key_parameters_ = derived_key_parameters.Clone();
  return *this;
}

absl::StatusOr<PrfBasedKeyDerivationParameters>
PrfBasedKeyDerivationParameters::Builder::Build() {
  if (prf_parameters_ == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "PRF parameters must be set.");
  }
  if (derived_key_parameters_ == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Derived key parameters must be set.");
  }

  const PrfParameters* prf_params =
      dynamic_cast<const PrfParameters*>(prf_parameters_.get());
  if (prf_params == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "PRF parameters cannot be set to non-PRF parameters.");
  }

  return PrfBasedKeyDerivationParameters(
      absl::WrapUnique(
          dynamic_cast<const PrfParameters*>(prf_parameters_.release())),
      std::move(derived_key_parameters_));
}

bool PrfBasedKeyDerivationParameters::operator==(
    const Parameters& other) const {
  const PrfBasedKeyDerivationParameters* that =
      dynamic_cast<const PrfBasedKeyDerivationParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (*prf_parameters_ != *that->prf_parameters_) {
    return false;
  }
  if (*derived_key_parameters_ != *that->derived_key_parameters_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
