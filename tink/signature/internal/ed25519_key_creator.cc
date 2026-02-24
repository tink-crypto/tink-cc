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

#include "tink/signature/internal/ed25519_key_creator.h"

#include <memory>

#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_public_key.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<Ed25519PrivateKey>> CreateEd25519Key(
    const Ed25519Parameters& params, absl::optional<int> id_requirement) {
  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  if (!key_pair.ok()) {
    return key_pair.status();
  }
  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      params, (*key_pair)->public_key, id_requirement, GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }
  absl::StatusOr<Ed25519PrivateKey> private_key = Ed25519PrivateKey::Create(
      *public_key,
      RestrictedData((*key_pair)->private_key,
                     GetInsecureSecretKeyAccessInternal()),
      GetPartialKeyAccess());
  if (!private_key.ok()) {
    return private_key.status();
  }
  return std::make_unique<Ed25519PrivateKey>(*private_key);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
