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

#ifndef TINK_SIGNATURE_SUBTLE_CREATE_ML_DSA_PREHASH_H_
#define TINK_SIGNATURE_SUBTLE_CREATE_ML_DSA_PREHASH_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/prehash.h"

namespace crypto {
namespace tink {
namespace subtle {

// Creates a new Prehash primitive for the given ML-DSA `key`.
absl::StatusOr<std::unique_ptr<Prehash>> CreateMlDsaPrehash(
    const MlDsaPublicKey& key);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_SUBTLE_CREATE_ML_DSA_PREHASH_H_
