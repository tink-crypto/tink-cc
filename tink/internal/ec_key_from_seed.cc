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
///////////////////////////////////////////////////////////////////////////////
#include "tink/internal/ec_key_from_seed.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "openssl/ec.h"
#include "openssl/ec_key.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/secret_data.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::subtle::EllipticCurveType;

absl::StatusOr<EcKey> NewEcKeyFromSeed(EllipticCurveType curve_type,
                                       const SecretData& secret_seed) {
  if (IsFipsModeEnabled()) {
    return absl::Status(
        absl::StatusCode::kInternal,
        "Deriving EC keys from a secret seed is not allowed in FIPS mode");
  }
  if (curve_type == EllipticCurveType::CURVE25519) {
    return absl::Status(
        absl::StatusCode::kInternal,
        "Creating a X25519 key from a secret seed is not supported");
  }
  absl::StatusOr<SslUniquePtr<EC_GROUP>> group =
      EcGroupFromCurveType(curve_type);
  if (!group.ok()) {
    return group.status();
  }
  SslUniquePtr<EC_KEY> key(EC_KEY_derive_from_secret(
      group->get(), secret_seed.data(), secret_seed.size()));
  if (key.get() == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "EC_KEY_derive_from_secret failed");
  }
  return EcKeyFromSslEcKey(curve_type, *key);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
