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

#ifndef TINK_SIGNATURE_INTERNAL_TESTING_SLH_DSA_TEST_VECTORS_H_
#define TINK_SIGNATURE_INTERNAL_TESTING_SLH_DSA_TEST_VECTORS_H_

#include <vector>

#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/slh_dsa_parameters.h"

namespace crypto {
namespace tink {
namespace internal {

// Returns static test vectors for SLH-DSA from BoringSSL slh_dsa.inc and Tink
// Go.
const std::vector<SignatureTestVector>& CreateSlhDsaTestVectors();

// Returns static test vector for SLH-DSA for the given hash type, signature
// type, and variant from BoringSSL slh_dsa.inc and Tink Go.
const SignatureTestVector& GetSlhDsaTestVector(
    SlhDsaParameters::HashType hash_type,
    SlhDsaParameters::SignatureType sig_type,
    SlhDsaParameters::Variant variant);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_TESTING_SLH_DSA_TEST_VECTORS_H_
