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
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_JWT_INTERNAL_TESTING_JWT_ML_DSA_TEST_VECTORS_H_
#define TINK_JWT_INTERNAL_TESTING_JWT_ML_DSA_TEST_VECTORS_H_

#include <string>

#include "tink/jwt/jwt_ml_dsa_parameters.h"

namespace crypto::tink::jwt_internal {

struct JwtMlDsaTestVector {
  JwtMlDsaParameters::Algorithm algorithm;
  std::string public_key_bytes;
  std::string private_seed_bytes;
};

// Returns ML-DSA-44 test vector from jwt_ml_dsa_signer_verifier_test.cc.
const JwtMlDsaTestVector& CreateJwtMlDsa44TestVector();

// Returns ML-DSA-65 test vector from jwt_ml_dsa_signer_verifier_test.cc.
const JwtMlDsaTestVector& CreateJwtMlDsa65TestVector();

// Returns ML-DSA-87 test vector from jwt_ml_dsa_signer_verifier_test.cc.
const JwtMlDsaTestVector& CreateJwtMlDsa87TestVector();

// Returns static test vector for JWT ML-DSA for the given algorithm.
const JwtMlDsaTestVector& GetJwtMlDsaTestVector(
    JwtMlDsaParameters::Algorithm algorithm);

}  // namespace crypto::tink::jwt_internal

#endif  // TINK_JWT_INTERNAL_TESTING_JWT_ML_DSA_TEST_VECTORS_H_
