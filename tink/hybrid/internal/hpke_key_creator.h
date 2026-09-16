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

#ifndef TINK_HYBRID_INTERNAL_HPKE_KEY_CREATOR_H_
#define TINK_HYBRID_INTERNAL_HPKE_KEY_CREATOR_H_

#include <optional>

#include "absl/status/statusor.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"

namespace crypto {
namespace tink {
namespace internal {

// Creates a new HpkePrivateKey from `parameters`.
// If `parameters` require a key ID, `id_requirement` must have a value.
// Otherwise it must be empty.
absl::StatusOr<HpkePrivateKey> CreatePrivateHpkeKey(
    const HpkeParameters& parameters, std::optional<int> id_requirement);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_KEY_CREATOR_H_
