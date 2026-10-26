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

#ifndef TINK_SIGNATURE_INTERNAL_TESTING_ML_DSA_MU_TEST_VECTORS_H_
#define TINK_SIGNATURE_INTERNAL_TESTING_ML_DSA_MU_TEST_VECTORS_H_

#include <string>
#include <vector>

#include "tink/signature/ml_dsa_parameters.h"

namespace crypto::tink::internal {

// Test vector for the ML-DSA external mu computation (FIPS 204, Algorithm 7,
// line 6) with an empty context.
struct MlDsaMuTestVector {
  MlDsaParameters::Instance instance;
  std::string public_key_bytes;
  std::string message;
  std::string mu;
};

// Returns static test vectors for the ML-DSA external mu computation for
// ML-DSA-44, ML-DSA-65, and ML-DSA-87. The test vectors come from BoringSSL,
// not from the standard Wycheproof test vectors.
const std::vector<MlDsaMuTestVector>& CreateMlDsaMuTestVectors();

}  // namespace crypto::tink::internal

#endif  // TINK_SIGNATURE_INTERNAL_TESTING_ML_DSA_MU_TEST_VECTORS_H_
