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
#ifndef TINK_SIGNATURE_INTERNAL_KEY_CREATORS_H_
#define TINK_SIGNATURE_INTERNAL_KEY_CREATORS_H_

#include <memory>

#include "absl/types/optional.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/signature/slh_dsa_private_key.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Creates a new ML-DSA private key from `parameters`. If `id_requirement` is
// set, the key will have the specified ID requirement. Otherwise, the key will
// have no ID requirement.
util::StatusOr<std::unique_ptr<MlDsaPrivateKey>> CreateMlDsaKey(
    const MlDsaParameters& params, absl::optional<int> id_requirement);

// Creates a new SLH-DSA private key from `parameters`. If `id_requirement` is
// set, the key will have the specified ID requirement. Otherwise, the key will
// have no ID requirement.
util::StatusOr<std::unique_ptr<SlhDsaPrivateKey>> CreateSlhDsaKey(
    const SlhDsaParameters& params, absl::optional<int> id_requirement);

// Creates a new ECDSA private key from `parameters`. If `id_requirement` is
// set, the key will have the specified ID requirement. Otherwise, the key will
// have no ID requirement.
util::StatusOr<std::unique_ptr<EcdsaPrivateKey>> CreateEcdsaKey(
    const EcdsaParameters& params, absl::optional<int> id_requirement);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_KEY_CREATORS_H_
