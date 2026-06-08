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

#ifndef TINK_JWT_INTERNAL_JWT_ML_DSA_KEY_CREATOR_H_
#define TINK_JWT_INTERNAL_JWT_ML_DSA_KEY_CREATOR_H_

#include <memory>

#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/jwt/jwt_ml_dsa_private_key.h"

namespace crypto {
namespace tink {
namespace internal {

// Creates a new JWT ML-DSA private key from `parameters`. If `id_requirement`
// is set, the key will have the specified ID requirement. Otherwise, the key
// will have no ID requirement.
//
// NOTE: Tink does not allow random generation of JWT ML-DSA key objects from
// parameters objects with `KidStrategy::kCustom`, so there is no corresponding
// parameter to specify a custom kid.
//
// This function unconditionally returns an error in non-BoringSSL builds.
absl::StatusOr<std::unique_ptr<JwtMlDsaPrivateKey>> CreateJwtMlDsaKey(
    const JwtMlDsaParameters& parameters, absl::optional<int> id_requirement);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_ML_DSA_KEY_CREATOR_H_
