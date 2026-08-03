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

#ifndef TINK_PRF_INTERNAL_HKDF_PRF_TEST_VECTORS_H_
#define TINK_PRF_INTERNAL_HKDF_PRF_TEST_VECTORS_H_

#include <string>
#include <vector>

#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"

namespace crypto::tink::internal {

struct HkdfPrfTestVector {
  HkdfPrfKey key;
  std::string input;
  std::string output;
};

// Returns static test vectors for HKDF PRF from RFC 5869.
const std::vector<HkdfPrfTestVector>& CreateHkdfPrfTestVectors();

// Returns static test vector for HKDF PRF for the given key size in bytes and
// hash type from RFC 5869.
const HkdfPrfTestVector& GetHkdfPrfTestVector(
    int key_size_in_bytes, HkdfPrfParameters::HashType hash_type);

}  // namespace crypto::tink::internal

#endif  // TINK_PRF_INTERNAL_HKDF_PRF_TEST_VECTORS_H_
