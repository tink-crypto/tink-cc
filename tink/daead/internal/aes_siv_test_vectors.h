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

#ifndef TINK_DAEAD_INTERNAL_AES_SIV_TEST_VECTORS_H_
#define TINK_DAEAD_INTERNAL_AES_SIV_TEST_VECTORS_H_

#include <string>
#include <vector>

#include "tink/daead/aes_siv_key.h"
#include "tink/daead/aes_siv_parameters.h"

namespace crypto::tink::internal {

struct AesSivTestVector {
  AesSivKey key;
  std::string plaintext;
  std::string aad;
  std::string ciphertext;
};

// Returns static test vectors for AES-SIV from Wycheproof
// (wycheproof/testvectors/aes_siv_cmac_test.json).
const std::vector<AesSivTestVector>& CreateAesSivTestVectors();

// Returns static test vector for AES-SIV for the given key size in bytes and
// variant from Wycheproof (wycheproof/testvectors/aes_siv_cmac_test.json).
const AesSivTestVector& GetAesSivTestVector(int key_size_in_bytes,
                                            AesSivParameters::Variant variant);

}  // namespace crypto::tink::internal

#endif  // TINK_DAEAD_INTERNAL_AES_SIV_TEST_VECTORS_H_
