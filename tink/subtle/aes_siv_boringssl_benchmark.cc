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

#include <memory>
#include <string>

#include "benchmark/benchmark.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/config/tink_fips.h"
#include "tink/deterministic_aead.h"
#include "tink/secret_data.h"
#include "tink/subtle/aes_siv_boringssl.h"
#include "tink/subtle/random.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

void AesSivEncryptBenchmark(benchmark::State& state) {
  if (IsFipsModeEnabled()) {
    state.SetLabel("Not supported in FIPS-only mode");
    return;
  }
  SecretData key = subtle::Random::GetRandomKeyBytes(64);
  absl::StatusOr<std::unique_ptr<DeterministicAead>> cipher =
      AesSivBoringSsl::New(key);
  ABSL_CHECK_OK(cipher.status());
  std::string data(state.range(0), 'x');
  benchmark::DoNotOptimize(data);
  for (auto s : state) {
    absl::StatusOr<std::string> ct =
        (*cipher)->EncryptDeterministically(data, "aad");
    benchmark::DoNotOptimize(ct);
    ABSL_CHECK_OK(ct.status());
  }
  state.SetBytesProcessed(state.iterations() * state.range(0));
}
BENCHMARK(AesSivEncryptBenchmark)->RangeMultiplier(128)->Range(32, 1 << 23);

void AesSivDecryptBenchmark(benchmark::State& state) {
  if (IsFipsModeEnabled()) {
    state.SetLabel("Not supported in FIPS-only mode");
    return;
  }
  SecretData key = subtle::Random::GetRandomKeyBytes(64);
  absl::StatusOr<std::unique_ptr<DeterministicAead>> cipher =
      AesSivBoringSsl::New(key);
  ABSL_CHECK_OK(cipher.status());
  std::string data(state.range(0), 'x');
  absl::StatusOr<std::string> ct =
      (*cipher)->EncryptDeterministically(data, "aad");
  ABSL_CHECK_OK(ct.status());
  absl::Status status;
  for (auto s : state) {
    benchmark::DoNotOptimize(
        status = (*cipher)->DecryptDeterministically(*ct, "aad").status());
    ABSL_CHECK_OK(status);
  }
  state.SetBytesProcessed(state.iterations() * state.range(0));
}
BENCHMARK(AesSivDecryptBenchmark)->RangeMultiplier(128)->Range(32, 1 << 23);

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
