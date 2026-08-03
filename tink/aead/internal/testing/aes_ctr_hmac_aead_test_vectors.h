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

#ifndef TINK_AEAD_INTERNAL_TESTING_AES_CTR_HMAC_AEAD_TEST_VECTORS_H_
#define TINK_AEAD_INTERNAL_TESTING_AES_CTR_HMAC_AEAD_TEST_VECTORS_H_

#include <vector>

#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"

namespace crypto::tink::internal {

// Returns static test vectors for AES-CTR-HMAC-AEAD from RFC 3602 (AES-CTR) and
// RFC 2104 / RFC 4231 (HMAC-SHA256).
const std::vector<AeadTestVector>& CreateAesCtrHmacAeadTestVectors();

// Returns static test vector for AES-CTR-HMAC-AEAD for the given AES key size
// in bytes and variant from RFC 3602, RFC 2104, and RFC 4231.
const AeadTestVector& GetAesCtrHmacAeadTestVector(
    int aes_key_size_in_bytes, AesCtrHmacAeadParameters::Variant variant);

}  // namespace crypto::tink::internal

#endif  // TINK_AEAD_INTERNAL_TESTING_AES_CTR_HMAC_AEAD_TEST_VECTORS_H_
