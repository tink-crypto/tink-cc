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

#ifndef TINK_SIGNATURE_INTERNAL_TESTING_RSA_SSA_PSS_TEST_VECTORS_H_
#define TINK_SIGNATURE_INTERNAL_TESTING_RSA_SSA_PSS_TEST_VECTORS_H_

#include <vector>

#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"

namespace crypto::tink::internal {

// Returns static test vectors for RSA SSA PSS from Tink Java
// (RsaSsaPssTestUtil.java).
const std::vector<SignatureTestVector>& CreateRsaSsaPssTestVectors();

// Valid 2048-bit, 3072-bit, and 4096-bit test vectors for use in tests from
// Wycheproof and Tink Java.
const SignatureTestVector& Create2048BitTestVector();
const SignatureTestVector& Create3072BitTestVector();
const SignatureTestVector& CreateWycheproof3072BitTestVector();
const SignatureTestVector& Create4096BitTestVector();
const SignatureTestVector& CreateWycheproof4096BitTestVector();

// Returns static test vector for RSA-SSA-PSS for the given modulus size,
// signature hash type, and variant.
const SignatureTestVector& GetRsaSsaPssTestVector(
    int modulus_size_in_bits, RsaSsaPssParameters::HashType sig_hash_type,
    RsaSsaPssParameters::Variant variant);

}  // namespace crypto::tink::internal

#endif  // TINK_SIGNATURE_INTERNAL_TESTING_RSA_SSA_PSS_TEST_VECTORS_H_
