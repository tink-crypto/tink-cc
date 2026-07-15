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
// Every header in BoringSSL includes base.h, which in turn defines
// OPENSSL_IS_BORINGSSL. So we include this common header upfront here to
// "force" the definition of OPENSSL_IS_BORINGSSL in case BoringSSL is used.
#include "openssl/crypto.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/mldsa.h"
#endif
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> CreateMlDsaKey(
    const MlDsaParameters& params, absl::optional<int> id_requirement) {
#ifndef OPENSSL_IS_BORINGSSL
  return absl::UnimplementedError(
      "ML-DSA is only supported in BoringSSL builds.");
#else
  absl::StatusOr<MlDsaPrivateKey> key = MlDsaPrivateKey::Create(
      params, RestrictedData(MLDSA_SEED_BYTES), id_requirement,
      GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return std::make_unique<MlDsaPrivateKey>(*key);
#endif  // OPENSSL_IS_BORINGSSL
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
