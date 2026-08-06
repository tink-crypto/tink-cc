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

#ifndef TINK_AEAD_INTERNAL_TESTING_X_AES_GCM_TEST_VECTORS_H_
#define TINK_AEAD_INTERNAL_TESTING_X_AES_GCM_TEST_VECTORS_H_

#include <vector>

#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/x_aes_gcm_parameters.h"

namespace crypto::tink::internal {

// Returns static test vectors for X-AES-GCM from Go and C2SP test vectors.
const std::vector<AeadTestVector>& CreateXAesGcmTestVectors();

// Returns static test vector for X-AES-GCM for the given salt size in bytes and
// variant.
const AeadTestVector& GetXAesGcmTestVector(int salt_size_in_bytes,
                                           XAesGcmParameters::Variant variant);

}  // namespace crypto::tink::internal

#endif  // TINK_AEAD_INTERNAL_TESTING_X_AES_GCM_TEST_VECTORS_H_
