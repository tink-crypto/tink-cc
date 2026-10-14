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
#ifndef TINK_INTERNAL_EC_KEY_FROM_SEED_H_
#define TINK_INTERNAL_EC_KEY_FROM_SEED_H_

#include "absl/status/statusor.h"
#include "tink/internal/ec_util.h"
#include "tink/secret_data.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace internal {

// Returns a new EC key for the specified curve derived from a secret seed.
//
// Fails in FIPS-only mode and for CURVE25519. This relies on BoringSSL's
// EC_KEY_derive_from_secret, so it returns kUnimplemented in builds that use
// OpenSSL instead of BoringSSL.
absl::StatusOr<EcKey> NewEcKeyFromSeed(
    crypto::tink::subtle::EllipticCurveType curve_type,
    const SecretData& secret_seed);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_EC_KEY_FROM_SEED_H_
