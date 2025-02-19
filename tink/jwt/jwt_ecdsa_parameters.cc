// Copyright 2024 Google LLC
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

#include "tink/jwt/jwt_ecdsa_parameters.h"

#include <set>

#include "absl/status/status.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

absl::StatusOr<JwtEcdsaParameters> JwtEcdsaParameters::Create(
    KidStrategy kid_strategy, Algorithm algorithm) {
  static const std::set<KidStrategy>* kSupportedKidStrategies =
      new std::set<KidStrategy>({KidStrategy::kBase64EncodedKeyId,
                                 KidStrategy::kIgnored, KidStrategy::kCustom});
  if (kSupportedKidStrategies->find(kid_strategy) ==
      kSupportedKidStrategies->end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create JWT ECDSA parameters with unknown kid strategy.");
  }
  static const std::set<Algorithm>* kSupportedAlgorithms =
      new std::set<Algorithm>(
          {Algorithm::kEs256, Algorithm::kEs384, Algorithm::kEs512});
  if (kSupportedAlgorithms->find(algorithm) == kSupportedAlgorithms->end()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create JWT ECDSA parameters with unknown algorithm.");
  }
  return JwtEcdsaParameters(kid_strategy, algorithm);
}

bool JwtEcdsaParameters::operator==(const Parameters& other) const {
  const JwtEcdsaParameters* that =
      dynamic_cast<const JwtEcdsaParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (kid_strategy_ != that->kid_strategy_) {
    return false;
  }
  if (algorithm_ != that->algorithm_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
