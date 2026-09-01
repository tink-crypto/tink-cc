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

#include "tink/signature/internal/ml_dsa_key_creator.h"

#include <memory>

#include "absl/memory/memory.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> CreateMlDsaKey(
    const MlDsaParameters& params, absl::optional<int> id_requirement) {
  // ML-DSA private key seed length is 32 bytes (NIST FIPS 204).
  constexpr int kSeedSizeBytes = 32;
  absl::StatusOr<MlDsaPrivateKey> key =
      MlDsaPrivateKey::Create(params, RestrictedData(kSeedSizeBytes),
                              id_requirement, GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return std::make_unique<MlDsaPrivateKey>(*key);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
