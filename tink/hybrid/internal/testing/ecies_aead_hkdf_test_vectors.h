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

#ifndef TINK_HYBRID_INTERNAL_TESTING_ECIES_AEAD_HKDF_TEST_VECTORS_H_
#define TINK_HYBRID_INTERNAL_TESTING_ECIES_AEAD_HKDF_TEST_VECTORS_H_

#include <string>
#include <vector>

#include "tink/ec_point.h"
#include "tink/hybrid/ecies_private_key.h"
#include "tink/hybrid/internal/testing/hybrid_test_vectors.h"
#include "tink/internal/ec_util.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"

namespace crypto::tink::internal {

// Returns P-256 public point from RFC 6979, Appendix A.2.5.
EcPoint P256Point();
// Returns P-256 private key from RFC 6979, Appendix A.2.5.
RestrictedData P256SecretValue();
// Returns P-384 public point from RFC 6979, Appendix A.2.6.
EcPoint P384Point();
// Returns P-384 private key from RFC 6979, Appendix A.2.6.
RestrictedData P384SecretValue();
// Returns P-521 public point from RFC 6979, Appendix A.2.7.
EcPoint P521Point();
// Returns P-521 private key from RFC 6979, Appendix A.2.7.
RestrictedData P521SecretValue();
std::string X25519PublicValue();
RestrictedData X25519SecretValue();

// Returns static test vectors for ECIES-AEAD-HKDF from RFC 6979 and Wycheproof.
const std::vector<HybridTestVector>& CreateEciesTestVectors();

// Returns a valid static ECIES private key for the given curve type from RFC
// 6979.
const EciesPrivateKey* GetEciesPrivateKey(subtle::EllipticCurveType curve_type);

// Returns a valid static EC key for the given curve type from RFC 6979.
const internal::EcKey& GetEcKey(subtle::EllipticCurveType curve_type);

}  // namespace crypto::tink::internal

#endif  // TINK_HYBRID_INTERNAL_TESTING_ECIES_AEAD_HKDF_TEST_VECTORS_H_
