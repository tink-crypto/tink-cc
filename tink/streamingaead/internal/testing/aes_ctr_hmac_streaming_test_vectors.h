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

#ifndef TINK_STREAMINGAEAD_INTERNAL_TESTING_AES_CTR_HMAC_STREAMING_TEST_VECTORS_H_
#define TINK_STREAMINGAEAD_INTERNAL_TESTING_AES_CTR_HMAC_STREAMING_TEST_VECTORS_H_

#include <vector>

#include "tink/streamingaead/internal/testing/streamingaead_test_vector.h"

namespace crypto {
namespace tink {
namespace internal {

// Returns static test vectors for AES-CTR-HMAC Streaming AEAD.
const std::vector<StreamingAeadTestVector>&
CreateAesCtrHmacStreamingTestVectors();

// Returns a static test vector for AES-CTR-HMAC Streaming AEAD for the given
// key size in bytes.
const StreamingAeadTestVector& GetAesCtrHmacStreamingTestVector(
    int key_size_in_bytes);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMINGAEAD_INTERNAL_TESTING_AES_CTR_HMAC_STREAMING_TEST_VECTORS_H_
