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

#ifndef TINK_SIGNATURE_INTERNAL_TESTING_COMPOSITE_ML_DSA_TEST_VECTORS_H_
#define TINK_SIGNATURE_INTERNAL_TESTING_COMPOSITE_ML_DSA_TEST_VECTORS_H_

#include <vector>

#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/internal/testing/signature_test_vector.h"

namespace crypto {
namespace tink {
namespace internal {

// Composite ML-DSA test vectors from
// https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-14#appendix-E.

SignatureTestVector CreateMlDsa44Ed25519TestVector(
    CompositeMlDsaParameters::Variant variant =
        CompositeMlDsaParameters::Variant::kNoPrefix);
SignatureTestVector CreateMlDsa44EcdsaP256TestVector(
    CompositeMlDsaParameters::Variant variant =
        CompositeMlDsaParameters::Variant::kNoPrefix);
SignatureTestVector CreateMlDsa65Ed2551TestVector(
    CompositeMlDsaParameters::Variant variant =
        CompositeMlDsaParameters::Variant::kNoPrefix);
SignatureTestVector CreateMlDsa65EcdsaP256TestVector(
    CompositeMlDsaParameters::Variant variant =
        CompositeMlDsaParameters::Variant::kNoPrefix);
SignatureTestVector CreateMlDsa65EcdsaP384TestVector(
    CompositeMlDsaParameters::Variant variant =
        CompositeMlDsaParameters::Variant::kNoPrefix);
SignatureTestVector CreateMlDsa65EcdsaRsa3072PssTestVector(
    CompositeMlDsaParameters::Variant variant =
        CompositeMlDsaParameters::Variant::kNoPrefix);
SignatureTestVector CreateMlDsa65EcdsaRsa4096PssTestVector(
    CompositeMlDsaParameters::Variant variant =
        CompositeMlDsaParameters::Variant::kNoPrefix);
SignatureTestVector CreateMlDsa65EcdsaRsa3072Pkcs1TestVector(
    CompositeMlDsaParameters::Variant variant =
        CompositeMlDsaParameters::Variant::kNoPrefix);
SignatureTestVector CreateMlDsa65EcdsaRsa4096Pkcs1TestVector(
    CompositeMlDsaParameters::Variant variant =
        CompositeMlDsaParameters::Variant::kNoPrefix);
SignatureTestVector CreateMlDsa87EcdsaP384TestVector(
    CompositeMlDsaParameters::Variant variant =
        CompositeMlDsaParameters::Variant::kNoPrefix);
SignatureTestVector CreateMlDsa87EcdsaP521TestVector(
    CompositeMlDsaParameters::Variant variant =
        CompositeMlDsaParameters::Variant::kNoPrefix);
SignatureTestVector CreateMlDsa87EcdsaRsa3072PssTestVector(
    CompositeMlDsaParameters::Variant variant =
        CompositeMlDsaParameters::Variant::kNoPrefix);
SignatureTestVector CreateMlDsa87EcdsaRsa4096PssTestVector(
    CompositeMlDsaParameters::Variant variant =
        CompositeMlDsaParameters::Variant::kNoPrefix);

// Returns a vector of all composite ML-DSA test vectors.
std::vector<SignatureTestVector> CreateCompositeMlDsaTestVectors();

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_TESTING_COMPOSITE_ML_DSA_TEST_VECTORS_H_
