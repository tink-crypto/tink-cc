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

#ifndef TINK_SIGNATURE_INTERNAL_TESTING_COMPOSITE_ML_DSA_TEST_UTIL_H_
#define TINK_SIGNATURE_INTERNAL_TESTING_COMPOSITE_ML_DSA_TEST_UTIL_H_

#include <memory>
#include "absl/types/optional.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/composite_ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/signature_private_key.h"

namespace crypto {
namespace tink {
namespace internal {

// Generates a new ML-DSA private key with the given instance.
MlDsaPrivateKey GenerateMlDsaPrivateKeyForTestOrDie(
    CompositeMlDsaParameters::MlDsaInstance instance);

// Generates a new classical private key for the given algorithm. If
// force_random is true, the key is randomly generated. Otherwise, either a
// fixed key or a random key will be returned.
std::unique_ptr<SignaturePrivateKey> GenerateClassicalPrivateKeyForTestOrDie(
    CompositeMlDsaParameters::ClassicalAlgorithm algorithm, bool force_random);

// Generates a new composite ML-DSA private key with the given parameters. If
// force_random is true, the key is randomly generated. Otherwise, either a
// fixed key or a random key will be returned.
CompositeMlDsaPrivateKey GenerateCompositeMlDsaPrivateKeyForTestOrDie(
    const CompositeMlDsaParameters& parameters, bool force_random,
    absl::optional<int> id_requirement);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_TESTING_COMPOSITE_ML_DSA_TEST_UTIL_H_
