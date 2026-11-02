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

#ifndef TINK_JWT_INTERNAL_TESTING_JWT_HMAC_TEST_VECTORS_H_
#define TINK_JWT_INTERNAL_TESTING_JWT_HMAC_TEST_VECTORS_H_

#include <string>
#include <vector>

#include "tink/jwt/jwt_hmac_key.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/jwt/jwt_validator.h"

namespace crypto::tink::jwt_internal {

struct JwtHmacTestVector {
  JwtHmacKey key;
  std::string signed_jwt;
  JwtValidator validator;
};

// Returns static test vectors for JWT HMAC (HS256, HS384, HS512) using the
// 64-byte key from RFC 7515, Appendix A.1.
const std::vector<JwtHmacTestVector>& CreateJwtHmacTestVectors();

// Returns static test vector for JWT HMAC for the given algorithm.
const JwtHmacTestVector& GetJwtHmacTestVector(
    JwtHmacParameters::Algorithm algorithm);

}  // namespace crypto::tink::jwt_internal

#endif  // TINK_JWT_INTERNAL_TESTING_JWT_HMAC_TEST_VECTORS_H_
