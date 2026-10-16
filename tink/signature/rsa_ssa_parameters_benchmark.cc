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

#include "benchmark/benchmark.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"

namespace crypto {
namespace tink {
namespace {

constexpr int kModulusSizeInBits = 2048;

// Measures the cost of default-constructing a builder, which includes
// computing the default public exponent.
void BM_RsaSsaPkcs1ParametersDefaultBuilder(benchmark::State& state) {
  for (auto s : state) {
    RsaSsaPkcs1Parameters::Builder builder;
    benchmark::DoNotOptimize(builder);
  }
}

void BM_RsaSsaPkcs1ParametersBuild(benchmark::State& state) {
  for (auto s : state) {
    absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
        RsaSsaPkcs1Parameters::Builder()
            .SetModulusSizeInBits(kModulusSizeInBits)
            .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
            .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
            .Build();
    benchmark::DoNotOptimize(parameters);
    ABSL_CHECK_OK(parameters);
  }
}

void BM_RsaSsaPssParametersDefaultBuilder(benchmark::State& state) {
  for (auto s : state) {
    RsaSsaPssParameters::Builder builder;
    benchmark::DoNotOptimize(builder);
  }
}

void BM_RsaSsaPssParametersBuild(benchmark::State& state) {
  for (auto s : state) {
    absl::StatusOr<RsaSsaPssParameters> parameters =
        RsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(kModulusSizeInBits)
            .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
            .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
            .SetSaltLengthInBytes(32)
            .SetVariant(RsaSsaPssParameters::Variant::kTink)
            .Build();
    benchmark::DoNotOptimize(parameters);
    ABSL_CHECK_OK(parameters);
  }
}

BENCHMARK(BM_RsaSsaPkcs1ParametersDefaultBuilder);
BENCHMARK(BM_RsaSsaPkcs1ParametersBuild);
BENCHMARK(BM_RsaSsaPssParametersDefaultBuilder);
BENCHMARK(BM_RsaSsaPssParametersBuild);

}  // namespace
}  // namespace tink
}  // namespace crypto
