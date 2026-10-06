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
#include <vector>

#include "benchmark/benchmark.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/testing/rsa_ssa_pkcs1_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/subtle/rsa_ssa_pkcs1_sign_boringssl.h"
#include "tink/subtle/rsa_ssa_pkcs1_verify_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

RsaSsaPkcs1PrivateKey GetPrivateKey(RsaSsaPkcs1Parameters::Variant variant) {
  const internal::SignatureTestVector& test_vector =
      internal::GetRsaSsaPkcs1TestVector(
          2048, RsaSsaPkcs1Parameters::HashType::kSha256, variant);
  const RsaSsaPkcs1PrivateKey* private_key =
      dynamic_cast<const RsaSsaPkcs1PrivateKey*>(
          test_vector.signature_private_key.get());
  ABSL_CHECK(private_key != nullptr)
      << "Selected test vector is not an RsaSsaPkcs1PrivateKey.";
  return *private_key;
}

void RsaSsaPkcs1VerifyBenchmark(benchmark::State& state,
                                RsaSsaPkcs1Parameters::Variant variant) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    state.SetLabel("Not supported in FIPS-only mode without BoringCrypto");
    return;
  }
  RsaSsaPkcs1PrivateKey private_key = GetPrivateKey(variant);
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      RsaSsaPkcs1SignBoringSsl::New(private_key);
  ABSL_CHECK_OK(signer.status());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RsaSsaPkcs1VerifyBoringSsl::New(private_key.GetPublicKey());
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

void BM_RsaSsaPkcs1NoPrefixVerify(benchmark::State& state) {
  RsaSsaPkcs1VerifyBenchmark(state, RsaSsaPkcs1Parameters::Variant::kNoPrefix);
}

void BM_RsaSsaPkcs1LegacyVerify(benchmark::State& state) {
  RsaSsaPkcs1VerifyBenchmark(state, RsaSsaPkcs1Parameters::Variant::kLegacy);
}

constexpr int64_t kMaxDataSize = 1 << 23;  // 8 MiB

BENCHMARK(BM_RsaSsaPkcs1NoPrefixVerify)
    ->RangeMultiplier(128)
    ->Range(32, kMaxDataSize);
BENCHMARK(BM_RsaSsaPkcs1LegacyVerify)
    ->RangeMultiplier(128)
    ->Range(32, kMaxDataSize);

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
