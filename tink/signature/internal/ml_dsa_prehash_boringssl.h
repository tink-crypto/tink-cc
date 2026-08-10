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

#ifndef TINK_SIGNATURE_INTERNAL_ML_DSA_PREHASH_BORINGSSL_H_
#define TINK_SIGNATURE_INTERNAL_ML_DSA_PREHASH_BORINGSSL_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/prehash.h"

namespace crypto {
namespace tink {
namespace internal {

// Creates a new Prehash primitive using the ML-DSA implementation from
// BoringSSL with an empty context. It computes the external mu value for
// ML-DSA-44, ML-DSA-65, or ML-DSA-87, and for keys with output prefix types
// other than kNoPrefix it also prepends the external mu value with the
// prefix "0xff || big_endian(key_id)" (5 bytes in total); for kNoPrefix keys,
// the prefix is an empty string.
//
// This function unconditionally returns an error in non-BoringSSL builds.
absl::StatusOr<std::unique_ptr<Prehash>> NewMlDsaPrehashBoringSsl(
    MlDsaPublicKey public_key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_ML_DSA_PREHASH_BORINGSSL_H_
