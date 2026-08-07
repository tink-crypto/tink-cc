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

#ifndef TINK_KEYDERIVATION_INTERNAL_PRF_BASED_KEY_DERIVATION_TEST_VECTORS_H_
#define TINK_KEYDERIVATION_INTERNAL_PRF_BASED_KEY_DERIVATION_TEST_VECTORS_H_

#include <vector>

#include "tink/keyderivation/prf_based_key_derivation_key.h"

namespace crypto::tink::internal {

struct PrfBasedKeyDerivationTestVector {
  PrfBasedKeyDerivationKey key;
};

// Returns static test vectors for PRF-based key derivation from Tink Java
// (PrfBasedKeyDeriverTest.java).
const std::vector<PrfBasedKeyDerivationTestVector>&
CreatePrfBasedKeyDerivationTestVectors();

// Returns static test vector for PRF-based key derivation with HKDF PRF from
// Tink Java (PrfBasedKeyDeriverTest.java).
const PrfBasedKeyDerivationTestVector& GetPrfBasedKeyDerivationHkdfTestVector();

// Returns static test vector for PRF-based key derivation with AES-CMAC PRF
// from Tink Java (PrfBasedKeyDeriverTest.java).
const PrfBasedKeyDerivationTestVector&
GetPrfBasedKeyDerivationAesCmacTestVector();

}  // namespace crypto::tink::internal

#endif  // TINK_KEYDERIVATION_INTERNAL_PRF_BASED_KEY_DERIVATION_TEST_VECTORS_H_
