// Copyright 2025 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

#include <optional>

#include "benchmark/benchmark.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "tink/ec_point.h"
#include "tink/partial_key_access.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"

namespace crypto {
namespace tink {
namespace {

const EcdsaPublicKey& GetPublicKey(EcdsaParameters::CurveType curve) {
  EcdsaParameters::HashType hash_type;
  switch (curve) {
    case EcdsaParameters::CurveType::kNistP256:
      hash_type = EcdsaParameters::HashType::kSha256;
      break;
    case EcdsaParameters::CurveType::kNistP384:
      hash_type = EcdsaParameters::HashType::kSha384;
      break;
    case EcdsaParameters::CurveType::kNistP521:
      hash_type = EcdsaParameters::HashType::kSha512;
      break;
    default:
      ABSL_CHECK(false) << "Unsupported curve: " << static_cast<int>(curve);
  }
  const internal::SignatureTestVector& test_vector =
      internal::GetEcdsaTestVector(
          curve, hash_type, EcdsaParameters::SignatureEncoding::kIeeeP1363,
          EcdsaParameters::Variant::kNoPrefix);
  const EcdsaPrivateKey* private_key = dynamic_cast<const EcdsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ABSL_CHECK(private_key != nullptr)
      << "Selected test vector is not an EcdsaPrivateKey.";
  return private_key->GetPublicKey();
}

// Measures the cost of creating (and validating) an `EcdsaPublicKey`, which
// includes decoding the public point.
void EcdsaPublicKeyCreateBenchmark(benchmark::State& state,
                                   EcdsaParameters::CurveType curve) {
  const EcdsaPublicKey& public_key = GetPublicKey(curve);
  const EcdsaParameters& parameters = public_key.GetParameters();
  const EcPoint& public_point =
      public_key.GetPublicPoint(GetPartialKeyAccess());
  ABSL_CHECK_OK(EcdsaPublicKey::Create(parameters, public_point,
                                       /*id_requirement=*/std::nullopt,
                                       GetPartialKeyAccess()));

  for (auto s : state) {
    absl::StatusOr<EcdsaPublicKey> key = EcdsaPublicKey::Create(
        parameters, public_point, /*id_requirement=*/std::nullopt,
        GetPartialKeyAccess());
    benchmark::DoNotOptimize(key);
  }
}

void BM_EcdsaP256PublicKeyCreate(benchmark::State& state) {
  EcdsaPublicKeyCreateBenchmark(state, EcdsaParameters::CurveType::kNistP256);
}
BENCHMARK(BM_EcdsaP256PublicKeyCreate);

void BM_EcdsaP384PublicKeyCreate(benchmark::State& state) {
  EcdsaPublicKeyCreateBenchmark(state, EcdsaParameters::CurveType::kNistP384);
}
BENCHMARK(BM_EcdsaP384PublicKeyCreate);

void BM_EcdsaP521PublicKeyCreate(benchmark::State& state) {
  EcdsaPublicKeyCreateBenchmark(state, EcdsaParameters::CurveType::kNistP521);
}
BENCHMARK(BM_EcdsaP521PublicKeyCreate);

}  // namespace
}  // namespace tink
}  // namespace crypto
