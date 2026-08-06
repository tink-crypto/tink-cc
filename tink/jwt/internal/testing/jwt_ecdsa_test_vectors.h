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

#include <string>

#include "tink/subtle/common_enums.h"

namespace crypto::tink::jwt_internal {

struct JwtEcdsaTestVector {
  subtle::EllipticCurveType curve;
  std::string pub_x;
  std::string pub_y;
  std::string priv;
};

// Returns P-256 (ES256) test vector from RFC 6979, Appendix A.2.5.
const JwtEcdsaTestVector& CreateJwtEcdsaP256TestVector();

// Returns valid P-256 (ES256) test vector from Wycheproof
// ecdsa_secp256r1_sha256_test.json.
const JwtEcdsaTestVector& CreateJwtEcdsaP256WycheproofTestVector();

// Returns P-384 (ES384) test vector from RFC 6979, Appendix A.2.6.
const JwtEcdsaTestVector& CreateJwtEcdsaP384TestVector();

// Returns P-521 (ES512) test vector from RFC 6979, Appendix A.2.7.
const JwtEcdsaTestVector& CreateJwtEcdsaP521TestVector();

// Returns static test vector for JWT ECDSA for the given curve.
const JwtEcdsaTestVector& GetJwtEcdsaTestVector(
    subtle::EllipticCurveType curve);

}  // namespace crypto::tink::jwt_internal

#endif  // TINK_JWT_INTERNAL_TESTING_JWT_ECDSA_TEST_VECTORS_H_
