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

#ifndef TINK_KEYDERIVATION_INTERNAL_PRF_BASED_KEY_DERIVATION_KEY_CREATOR_H_
#define TINK_KEYDERIVATION_INTERNAL_PRF_BASED_KEY_DERIVATION_KEY_CREATOR_H_

#include <memory>
#include <optional>

#include "absl/status/statusor.h"
#include "tink/key.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"

namespace crypto {
namespace tink {
namespace internal {

// Creates a new PRF-based key derivation key from `parameters` (supporting only
// `HkdfPrfParameters` as the underlying PRF parameters). If `id_requirement` is
// set, the key will have the specified ID requirement; otherwise, the key will
// have no ID requirement.
absl::StatusOr<std::unique_ptr<Key>> CreatePrfBasedKeyDerivationKey(
    const PrfBasedKeyDerivationParameters& parameters,
    std::optional<int> id_requirement);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYDERIVATION_INTERNAL_PRF_BASED_KEY_DERIVATION_KEY_CREATOR_H_
