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

#ifndef TINK_HYBRID_INTERNAL_TESTING_HPKE_TEST_VECTORS_H_
#define TINK_HYBRID_INTERNAL_TESTING_HPKE_TEST_VECTORS_H_

#include <memory>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/internal/testing/hybrid_test_vectors.h"
#include "tink/internal/mlkem_util.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"

namespace crypto::tink::internal {

struct HpkeNistCurveTestCase {
  subtle::EllipticCurveType curve;
  HpkeParameters::KemId kem_id;
  HpkeParameters::KdfId kdf_id;
  HpkeParameters::AeadId aead_id;
  HpkeParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
  std::shared_ptr<const HpkePrivateKey> private_key;
};

struct HpkeMlKemTestCase {
  HpkeParameters::KemId kem_id;
  MlKemKeySize key_size;
  int public_key_bytes;
  std::shared_ptr<const HpkePrivateKey> private_key;
};

struct HpkeKeyPairBytes {
  std::string public_key_bytes;
  RestrictedData private_key_bytes;
};

// NIST P-256 test key pair from RFC 6979, Appendix A.2.5.
std::string P256PointAsString();
RestrictedData P256SecretValue();

// NIST P-384 test key pair from RFC 6979, Appendix A.2.6.
std::string P384PointAsString();
RestrictedData P384SecretValue();

// NIST P-521 test key pair from RFC 6979, Appendix A.2.7.
std::string P521PointAsString();
RestrictedData P521SecretValue();

// X25519 test key pair from RFC 7748, Section 6.1.
std::string X25519PublicValue();
RestrictedData X25519SecretValue();

// X-Wing test key pair from RFC 9180 / draft-connolly-cfrg-xwing-kem-09.
std::string XWingPublicValue();
RestrictedData XWingSecretValue();

// ML-KEM-768 test key pair from NIST FIPS 203.
std::string MlKem768PublicValue();
RestrictedData MlKem768SecretValue();

// ML-KEM-1024 test key pair from NIST FIPS 203.
std::string MlKem1024PublicValue();
RestrictedData MlKem1024SecretValue();

// Returns static test vectors for HPKE from RFC 9180, NIST FIPS 203, and Tink
// Java (HpkeTestUtil.java).
const std::vector<HybridTestVector>& CreateHpkeTestVectors();

// Returns static test vector for HPKE for the given KEM, KDF, AEAD, and
// variant from RFC 9180, NIST FIPS 203, and Tink Java (HpkeTestUtil.java).
const HybridTestVector& GetHpkeTestVector(HpkeParameters::KemId kem_id,
                                          HpkeParameters::KdfId kdf_id,
                                          HpkeParameters::AeadId aead_id,
                                          HpkeParameters::Variant variant);

// Returns static test cases for HPKE NIST curves (P-256, P-384, P-521).
const std::vector<HpkeNistCurveTestCase>& CreateHpkeNistCurveTestCases();

// Returns static test case for the given NIST curve.
const HpkeNistCurveTestCase& GetHpkeNistCurveTestCase(
    subtle::EllipticCurveType curve);

// Returns static test cases for HPKE ML-KEM (ML-KEM-768, ML-KEM-1024).
const std::vector<HpkeMlKemTestCase>& CreateHpkeMlKemTestCases();

// Returns key pair bytes for NIST curves.
absl::StatusOr<HpkeKeyPairBytes> GetHpkeNistCurveKeyPairBytes(
    subtle::EllipticCurveType curve);

// Returns key pair bytes for ML-KEM.
HpkeKeyPairBytes GetHpkeMlKemKeyPairBytes(MlKemKeySize key_size);

// Returns key pair bytes for X25519.
HpkeKeyPairBytes GetHpkeX25519KeyPairBytes();

// Returns key pair bytes for X-Wing.
HpkeKeyPairBytes GetHpkeXWingKeyPairBytes();

}  // namespace crypto::tink::internal

#endif  // TINK_HYBRID_INTERNAL_TESTING_HPKE_TEST_VECTORS_H_
