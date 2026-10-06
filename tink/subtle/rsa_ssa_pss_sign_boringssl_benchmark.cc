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
///////////////////////////////////////////////////////////////////////////////

#include <cstdint>
#include <memory>
#include <string>

#include "benchmark/benchmark.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/signature/internal/testing/rsa_ssa_pss_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/subtle/rsa_ssa_pss_sign_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

const RsaSsaPssPrivateKey& GetPrivateKey(RsaSsaPssParameters::Variant variant) {
  const internal::SignatureTestVector& test_vector =
      internal::GetRsaSsaPssTestVector(
          2048, RsaSsaPssParameters::HashType::kSha256, variant);
  const RsaSsaPssPrivateKey* private_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          test_vector.signature_private_key.get());
  ABSL_CHECK(private_key != nullptr)
      << "Selected test vector is not an RsaSsaPssPrivateKey.";
  return *private_key;
}

void RsaSsaPssSignBenchmark(benchmark::State& state,
                            RsaSsaPssParameters::Variant variant) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    state.SetLabel("Not supported in FIPS-only mode without BoringCrypto");
    return;
  }
  const RsaSsaPssPrivateKey& private_key = GetPrivateKey(variant);
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      RsaSsaPssSignBoringSsl::New(private_key);
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

void BM_RsaSsaPssNoPrefixSign(benchmark::State& state) {
  RsaSsaPssSignBenchmark(state, RsaSsaPssParameters::Variant::kNoPrefix);
}

void BM_RsaSsaPssLegacySign(benchmark::State& state) {
  RsaSsaPssSignBenchmark(state, RsaSsaPssParameters::Variant::kLegacy);
}

constexpr int64_t kMaxDataSize = 1 << 23;  // 8 MiB

BENCHMARK(BM_RsaSsaPssNoPrefixSign)
    ->RangeMultiplier(128)
    ->Range(32, kMaxDataSize);
BENCHMARK(BM_RsaSsaPssLegacySign)
    ->RangeMultiplier(128)
    ->Range(32, kMaxDataSize);

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
