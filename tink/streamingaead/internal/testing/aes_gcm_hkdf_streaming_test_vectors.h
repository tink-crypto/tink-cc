// Copyright 2025 Google LLC
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

#ifndef TINK_STREAMINGAEAD_INTERNAL_TESTING_AES_GCM_HKDF_STREAMING_TEST_VECTORS_H_
#define TINK_STREAMINGAEAD_INTERNAL_TESTING_AES_GCM_HKDF_STREAMING_TEST_VECTORS_H_

#include <vector>

#include "tink/streamingaead/internal/testing/streamingaead_test_vector.h"

namespace crypto {
namespace tink {
namespace internal {

// Returns static test vectors for AES-GCM-HKDF Streaming AEAD from Tink's cross
// language tests
// (testing/cross_language/cross_language/streaming_aead/aes_gcm_hkdf_streaming_key_test.py)
// and Java tests
// (java_src/src/main/java/com/google/crypto/tink/streamingaead/internal/testing/AesGcmHkdfStreamingTestUtil.java).
const std::vector<StreamingAeadTestVector>&
CreateAesGcmHkdfStreamingTestVectors();

// Returns a static test vector for AES-GCM-HKDF Streaming AEAD for the given
// key size in bytes from Tink's cross language tests
// (testing/cross_language/cross_language/streaming_aead/aes_gcm_hkdf_streaming_key_test.py)
// and Java tests
// (java_src/src/main/java/com/google/crypto/tink/streamingaead/internal/testing/AesGcmHkdfStreamingTestUtil.java).
const StreamingAeadTestVector& GetAesGcmHkdfStreamingTestVector(
    int key_size_in_bytes);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMINGAEAD_INTERNAL_TESTING_AES_GCM_HKDF_STREAMING_TEST_VECTORS_H_
