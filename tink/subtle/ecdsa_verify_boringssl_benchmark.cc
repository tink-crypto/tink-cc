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
#include "tink/internal/fips_utils.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

void EcdsaVerifyBenchmark(benchmark::State& state,
                          EcdsaParameters::Variant variant) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    state.SetLabel("Not supported in FIPS-only mode without BoringCrypto");
    return;
  }
  const internal::SignatureTestVector& test_vector =
      internal::GetEcdsaTestVector(
          EcdsaParameters::CurveType::kNistP256,
          EcdsaParameters::HashType::kSha256,
          EcdsaParameters::SignatureEncoding::kIeeeP1363, variant);
  const auto* private_key = dynamic_cast<const EcdsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ABSL_CHECK(private_key != nullptr);
  absl::StatusOr<std::unique_ptr<EcdsaSignBoringSsl>> signer =
      EcdsaSignBoringSsl::New(*private_key);
  ABSL_CHECK_OK(signer.status());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      EcdsaVerifyBoringSsl::New(private_key->GetPublicKey());
  ABSL_CHECK_OK(verifier.status());

  std::string data(state.range(0), 'x');
  absl::StatusOr<std::string> signature = (*signer)->Sign(data);
  ABSL_CHECK_OK(signature.status());
  for (auto s : state) {
    benchmark::DoNotOptimize(data);
    benchmark::DoNotOptimize(signature);
    absl::Status status = (*verifier)->Verify(*signature, data);
    benchmark::DoNotOptimize(status);
    ABSL_CHECK_OK(status);
  }
  state.SetBytesProcessed(state.iterations() * state.range(0));
}

void BM_EcdsaP256NoPrefixVerify(benchmark::State& state) {
  EcdsaVerifyBenchmark(state, EcdsaParameters::Variant::kNoPrefix);
}

void BM_EcdsaP256LegacyVerify(benchmark::State& state) {
  EcdsaVerifyBenchmark(state, EcdsaParameters::Variant::kLegacy);
}

constexpr int64_t kMaxDataSize = 1 << 23;  // 8 MiB

BENCHMARK(BM_EcdsaP256NoPrefixVerify)
    ->RangeMultiplier(128)
    ->Range(32, kMaxDataSize);
BENCHMARK(BM_EcdsaP256LegacyVerify)
    ->RangeMultiplier(128)
    ->Range(32, kMaxDataSize);

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
