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
///////////////////////////////////////////////////////////////////////////////

#include "tink/experimental/pqcrypto/kem/internal/ml_kem_test_util.h"

#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mlkem_util.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<MlKemPrivateKey> GenerateMlKemPrivateKey(
    const MlKemParameters& key_parameters, absl::optional<int> id_requirement) {
  if (key_parameters.GetKeySize() != 768) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Only ML-KEM 768 is supported");
  }

  absl::StatusOr<MlKemKey> key = NewMlKemKey(MlKemKeySize::ML_KEM768);
  if (!key.ok()) {
    return key.status();
  }

  absl::StatusOr<MlKemPublicKey> public_key = MlKemPublicKey::Create(
      key_parameters, key->public_key, id_requirement, GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return MlKemPrivateKey::Create(
      *public_key,
      RestrictedData(std::move(key->private_key),
                     InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
