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

#ifndef TINK_PRF_INTERNAL_HKDF_PRF_KEY_CREATOR_H_
#define TINK_PRF_INTERNAL_HKDF_PRF_KEY_CREATOR_H_

#include <memory>
#include <optional>

#include "absl/status/statusor.h"
#include "tink/key.h"
#include "tink/prf/hkdf_prf_parameters.h"

namespace crypto {
namespace tink {
namespace internal {

// Creates a new HKDF-PRF key from `parameters`. Returns an error if
// `id_requirement` is set, since PRF keys do not have ID requirements.
absl::StatusOr<std::unique_ptr<Key>> CreateHkdfPrfKey(
    const HkdfPrfParameters& parameters, std::optional<int> id_requirement);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRF_INTERNAL_HKDF_PRF_KEY_CREATOR_H_
