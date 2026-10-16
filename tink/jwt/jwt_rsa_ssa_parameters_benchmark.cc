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
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"

namespace crypto {
namespace tink {
namespace {

constexpr int kModulusSizeInBits = 2048;

// Measures the cost of default-constructing a builder, which includes
// computing the default public exponent.
void BM_JwtRsaSsaPkcs1ParametersDefaultBuilder(benchmark::State& state) {
  for (auto s : state) {
    JwtRsaSsaPkcs1Parameters::Builder builder;
    benchmark::DoNotOptimize(builder);
  }
}

void BM_JwtRsaSsaPkcs1ParametersBuild(benchmark::State& state) {
  for (auto s : state) {
    absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
        JwtRsaSsaPkcs1Parameters::Builder()
            .SetModulusSizeInBits(kModulusSizeInBits)
            .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
            .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
            .Build();
    benchmark::DoNotOptimize(parameters);
    ABSL_CHECK_OK(parameters);
  }
}

void BM_JwtRsaSsaPssParametersDefaultBuilder(benchmark::State& state) {
  for (auto s : state) {
    JwtRsaSsaPssParameters::Builder builder;
    benchmark::DoNotOptimize(builder);
  }
}

void BM_JwtRsaSsaPssParametersBuild(benchmark::State& state) {
  for (auto s : state) {
    absl::StatusOr<JwtRsaSsaPssParameters> parameters =
        JwtRsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(kModulusSizeInBits)
            .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
            .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
            .Build();
    benchmark::DoNotOptimize(parameters);
    ABSL_CHECK_OK(parameters);
  }
}

BENCHMARK(BM_JwtRsaSsaPkcs1ParametersDefaultBuilder);
BENCHMARK(BM_JwtRsaSsaPkcs1ParametersBuild);
BENCHMARK(BM_JwtRsaSsaPssParametersDefaultBuilder);
BENCHMARK(BM_JwtRsaSsaPssParametersBuild);

}  // namespace
}  // namespace tink
}  // namespace crypto
