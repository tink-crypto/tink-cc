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

namespace crypto::tink::jwt_internal {

struct JwtHmacTestVector {
  std::string key;
};

// Returns a 256-bit (32-byte) HMAC key from Wycheproof json_web_key_test.json.
const JwtHmacTestVector& CreateJwtHmacKey32TestVector();

// Returns a 384-bit (48-byte) HMAC key from Go jwt_full_mac_test.go.
const JwtHmacTestVector& CreateJwtHmacKey48TestVector();

// Returns a 512-bit (64-byte) HMAC key from Go jwt_full_mac_test.go.
const JwtHmacTestVector& CreateJwtHmacKey64TestVector();

// Returns static test vector for JWT HMAC for the given key size in bytes.
const JwtHmacTestVector& GetJwtHmacTestVector(int key_size_in_bytes);

}  // namespace crypto::tink::jwt_internal

#endif  // TINK_JWT_INTERNAL_TESTING_JWT_HMAC_TEST_VECTORS_H_
