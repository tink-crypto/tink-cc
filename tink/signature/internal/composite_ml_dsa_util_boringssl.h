// Copyright 2026 Google LLC
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

#ifndef TINK_SIGNATURE_INTERNAL_COMPOSITE_ML_DSA_UTIL_BORINGSSL_H_
#define TINK_SIGNATURE_INTERNAL_COMPOSITE_ML_DSA_UTIL_BORINGSSL_H_

#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/signature/composite_ml_dsa_parameters.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::string> GetCompositeMlDsaLabel(
    const CompositeMlDsaParameters& parameters);

std::string ComputeCompositeMlDsaMessagePrime(absl::string_view label,
                                              absl::string_view message);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_COMPOSITE_ML_DSA_UTIL_BORINGSSL_H_
