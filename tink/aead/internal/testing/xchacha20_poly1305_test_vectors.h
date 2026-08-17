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

#ifndef TINK_AEAD_INTERNAL_TESTING_XCHACHA20_POLY1305_TEST_VECTORS_H_
#define TINK_AEAD_INTERNAL_TESTING_XCHACHA20_POLY1305_TEST_VECTORS_H_

#include <vector>

#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"

namespace crypto::tink::internal {

// Returns static test vectors for XChaCha20-Poly1305 from Wycheproof
// (wycheproof/testvectors/xchacha20_poly1305_test.json).
const std::vector<AeadTestVector>& CreateXChaCha20Poly1305TestVectors();

// Returns static test vector for XChaCha20-Poly1305 for the given variant from
// Wycheproof (wycheproof/testvectors/xchacha20_poly1305_test.json).
const AeadTestVector& GetXChaCha20Poly1305TestVector(
    XChaCha20Poly1305Parameters::Variant variant);

}  // namespace crypto::tink::internal

#endif  // TINK_AEAD_INTERNAL_TESTING_XCHACHA20_POLY1305_TEST_VECTORS_H_
