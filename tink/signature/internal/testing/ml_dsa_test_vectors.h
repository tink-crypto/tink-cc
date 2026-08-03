// Copyright 2024 Google LLC
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

#ifndef TINK_SIGNATURE_INTERNAL_TESTING_ML_DSA_TEST_VECTORS_H_
#define TINK_SIGNATURE_INTERNAL_TESTING_ML_DSA_TEST_VECTORS_H_

#include <vector>

#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/ml_dsa_parameters.h"

namespace crypto::tink::internal {

// Returns static test vectors for ML-DSA (ML-DSA-44, ML-DSA-65, and ML-DSA-87)
// from NIST FIPS 204.
const std::vector<SignatureTestVector>& CreateMlDsaTestVectors();

// Returns static test vector for ML-DSA for the given instance and variant from
// NIST FIPS 204.
const SignatureTestVector& GetMlDsaTestVector(
    MlDsaParameters::Instance instance, MlDsaParameters::Variant variant);

}  // namespace crypto::tink::internal

#endif  // TINK_SIGNATURE_INTERNAL_TESTING_ML_DSA_TEST_VECTORS_H_
