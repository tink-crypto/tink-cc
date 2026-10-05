// Copyright 2017 Google LLC
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

#include <cstdint>
#include <memory>
#include <string>

#include "benchmark/benchmark.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

const EcdsaPrivateKey& GetPrivateKey(
    EcdsaParameters::CurveType curve,
    EcdsaParameters::SignatureEncoding encoding =
        EcdsaParameters::SignatureEncoding::kIeeeP1363,
    EcdsaParameters::Variant variant = EcdsaParameters::Variant::kNoPrefix) {
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
      internal::GetEcdsaTestVector(curve, hash_type, encoding, variant);
  const EcdsaPrivateKey* private_key = dynamic_cast<const EcdsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ABSL_CHECK(private_key != nullptr)
      << "Selected test vector is not an EcdsaPrivateKey.";
  return *private_key;
}

void EcdsaSignBenchmark(benchmark::State& state,
                        EcdsaParameters::Variant variant) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    state.SetLabel("Not supported in FIPS-only mode without BoringCrypto");
    return;
  }
  const EcdsaPrivateKey& private_key =
      GetPrivateKey(EcdsaParameters::CurveType::kNistP256,
                    EcdsaParameters::SignatureEncoding::kIeeeP1363, variant);
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      EcdsaSignBoringSsl::New(private_key);
  ABSL_CHECK_OK(signer.status());

  std::string data(state.range(0), 'x');
  for (auto s : state) {
    benchmark::DoNotOptimize(data);
    absl::StatusOr<std::string> signature = (*signer)->Sign(data);
    benchmark::DoNotOptimize(signature);
    ABSL_CHECK_OK(signature.status());
  }
  state.SetBytesProcessed(state.iterations() * state.range(0));
}

void BM_EcdsaP256NoPrefixSign(benchmark::State& state) {
  EcdsaSignBenchmark(state, EcdsaParameters::Variant::kNoPrefix);
}

void BM_EcdsaP256LegacySign(benchmark::State& state) {
  EcdsaSignBenchmark(state, EcdsaParameters::Variant::kLegacy);
}

constexpr int64_t kMaxDataSize = 1 << 23;  // 8 MiB

BENCHMARK(BM_EcdsaP256NoPrefixSign)
    ->RangeMultiplier(128)
    ->Range(32, kMaxDataSize);
BENCHMARK(BM_EcdsaP256LegacySign)
    ->RangeMultiplier(128)
    ->Range(32, kMaxDataSize);

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
