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

#ifndef TINK_JWT_INTERNAL_TESTING_JWT_ECDSA_TEST_VECTORS_H_
#define TINK_JWT_INTERNAL_TESTING_JWT_ECDSA_TEST_VECTORS_H_

#include <vector>

#include "tink/jwt/jwt_ecdsa_private_key.h"
#include "tink/subtle/common_enums.h"

namespace crypto::tink::jwt_internal {

struct JwtEcdsaTestVector {
  JwtEcdsaPrivateKey key;
};

// Returns static test vectors for JWT ECDSA:
// - P-256 (ES256): RFC 6979, Appendix A.2.5
// - P-384 (ES384): RFC 6979, Appendix A.2.6
// - P-521 (ES512): RFC 6979, Appendix A.2.7
const std::vector<JwtEcdsaTestVector>& CreateJwtEcdsaTestVectors();

// Returns static test vector for JWT ECDSA for the given curve.
const JwtEcdsaTestVector& GetJwtEcdsaTestVector(
    subtle::EllipticCurveType curve);

// Returns static Wycheproof test vector for JWT ECDSA P-256
// (third_party/wycheproof/testvectors/json_web_crypto_test.json:165-174).
const JwtEcdsaTestVector& GetJwtEcdsaWycheproofTestVector();

}  // namespace crypto::tink::jwt_internal

#endif  // TINK_JWT_INTERNAL_TESTING_JWT_ECDSA_TEST_VECTORS_H_
