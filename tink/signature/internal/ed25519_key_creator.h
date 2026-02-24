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

#ifndef TINK_SIGNATURE_INTERNAL_ED25519_KEY_CREATOR_H_
#define TINK_SIGNATURE_INTERNAL_ED25519_KEY_CREATOR_H_

#include <memory>

#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"

namespace crypto {
namespace tink {
namespace internal {

// Creates a new Ed25519 private key from `parameters`. If `id_requirement` is
// set, the key will have the specified ID requirement. Otherwise, the key will
// have no ID requirement.
absl::StatusOr<std::unique_ptr<Ed25519PrivateKey>> CreateEd25519Key(
    const Ed25519Parameters& params, absl::optional<int> id_requirement);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_ED25519_KEY_CREATOR_H_
