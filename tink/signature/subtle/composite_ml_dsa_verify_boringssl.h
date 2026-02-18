// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_SIGNATURE_SUBTLE_COMPOSITE_ML_DSA_VERIFY_BORINGSSL_H_
#define TINK_SIGNATURE_SUBTLE_COMPOSITE_ML_DSA_VERIFY_BORINGSSL_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/low_level_crypto_access_token.h"
#include "tink/public_key_verify.h"
#include "tink/signature/composite_ml_dsa_public_key.h"

namespace crypto {
namespace tink {
namespace subtle {

// Creates a new PublicKeyVerify primitive using the existing ML-DSA and
// classical PublicKeyVerify primitives.
absl::StatusOr<std::unique_ptr<PublicKeyVerify>> NewCompositeMlDsaVerify(
    const CompositeMlDsaPublicKey& public_key, LowLevelCryptoAccessToken token);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_SUBTLE_COMPOSITE_ML_DSA_VERIFY_BORINGSSL_H_
