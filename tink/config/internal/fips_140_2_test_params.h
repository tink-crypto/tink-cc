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

#ifndef TINK_CONFIG_INTERNAL_FIPS_140_2_TEST_PARAMS_H_
#define TINK_CONFIG_INTERNAL_FIPS_140_2_TEST_PARAMS_H_

#include <memory>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "tink/parameters.h"

namespace crypto {
namespace tink {
namespace internal {

// A single test case for `ConfigFips140_2()` / `KeyGenConfigFips140_2()`.
struct Fips1402TestCase {
  // Human readable, unique name; only contains [A-Za-z0-9_] so that it can be
  // used as a gtest parameter name.
  std::string name;
  std::shared_ptr<const Parameters> params;
};

// The tables below are the authoritative list of parameters that are allowed
// (resp. not allowed) by `ConfigFips140_2()` and `KeyGenConfigFips140_2()`.

// Parameters for which key generation and primitive creation must succeed.
std::vector<Fips1402TestCase> AllowedAeadParameters();
std::vector<Fips1402TestCase> AllowedMacParameters();
std::vector<Fips1402TestCase> AllowedPrfParameters();
std::vector<Fips1402TestCase> AllowedSignatureParameters();

// Parameters for which key generation and primitive creation must fail.
//
// All of these parameters are valid and supported by Tink outside of the FIPS
// configs (e.g. by `KeyGenConfig2026()` / `Config2026()`).
std::vector<Fips1402TestCase> DeniedAeadParameters();
std::vector<Fips1402TestCase> DeniedMacParameters();
std::vector<Fips1402TestCase> DeniedPrfParameters();
std::vector<Fips1402TestCase> DeniedSignatureParameters();

// Registers the proto serializations of all the parameters and keys used in
// the tables above in the global serialization registry.
//
// This is needed because `KeyGenConfigFips140_2()` only registers legacy key
// managers: in order to generate a key from a `Parameters` object,
// `KeysetHandleBuilder` serializes the parameters to a proto key template,
// which requires the corresponding proto serialization to be registered.
absl::Status RegisterFips1402TestProtoSerializations();

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_CONFIG_INTERNAL_FIPS_140_2_TEST_PARAMS_H_
