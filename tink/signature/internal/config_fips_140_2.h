// Copyright 2023 Google LLC
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

#ifndef TINK_SIGNATURE_INTERNAL_CONFIG_FIPS_140_2_H_
#define TINK_SIGNATURE_INTERNAL_CONFIG_FIPS_140_2_H_

#include "tink/configuration.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

// Add FIPS 140-2-compliant Signature primitive wrappers and key managers to
// `config`, used to generate primitives.
absl::Status AddSignatureFips140_2(Configuration& config);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_CONFIG_FIPS_140_2_H_
