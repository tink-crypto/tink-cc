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

#ifndef TINK_MAC_INTERNAL_HMAC_TEST_VECTORS_H_
#define TINK_MAC_INTERNAL_HMAC_TEST_VECTORS_H_

#include <string>
#include <vector>

#include "tink/mac/hmac_key.h"
#include "tink/mac/hmac_parameters.h"

namespace crypto::tink::internal {

struct HmacTestVector {
  HmacKey key;
  std::string message;
  std::string tag;
};

// Returns static test vectors for HMAC from Wycheproof and Tink Java
// (HmacTestUtil.java).
const std::vector<HmacTestVector>& CreateHmacTestVectors();

// Returns static test vector for HMAC for the given key size in bytes, hash
// type, and variant from Wycheproof and Tink Java (HmacTestUtil.java).
const HmacTestVector& GetHmacTestVector(int key_size_in_bytes,
                                        HmacParameters::HashType hash_type,
                                        HmacParameters::Variant variant);

}  // namespace crypto::tink::internal

#endif  // TINK_MAC_INTERNAL_HMAC_TEST_VECTORS_H_
