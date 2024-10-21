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

#ifndef TINK_SIGNATURE_INTERNAL_TESTING_ED25519_TEST_VECTORS_H_
#define TINK_SIGNATURE_INTERNAL_TESTING_ED25519_TEST_VECTORS_H_

#include <vector>
#include "tink/signature/internal/testing/signature_test_vector.h"

namespace crypto {
namespace tink {
namespace internal {

// Provides some test vectors for Ed25519. These are the same as in Java,
// Ed25519TestUtil.createEd25519TestVectors (and were generated using Tink
// Java).
std::vector<SignatureTestVector> CreateEd25519TestVectors();

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_TESTING_ED25519_TEST_VECTORS_H_