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

#include "tink/signature/composite_ml_dsa_parameters.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/parameters.h"

namespace crypto {
namespace tink {

absl::StatusOr<CompositeMlDsaParameters> CompositeMlDsaParameters::Create(
    MlDsaInstance ml_dsa_instance, ClassicalAlgorithm classical_algorithm,
    Variant variant) {
  // We support the following combinations:
  //
  // MLDSA65-RSA3072-PSS-SHA512
  // MLDSA65-RSA3072-PKCS15-SHA512
  // MLDSA65-RSA4096-PSS-SHA512
  // MLDSA65-RSA4096-PKCS15-SHA512
  // MLDSA65-ECDSA-P256-SHA512
  // MLDSA65-ECDSA-P384-SHA512
  // MLDSA65-Ed25519-SHA512
  // MLDSA87-ECDSA-P384-SHA512
  // MLDSA87-ECDSA-P521-SHA512
  // MLDSA87-RSA3072-PSS-SHA512
  // MLDSA87-RSA4096-PSS-SHA512
  switch (ml_dsa_instance) {
    case MlDsaInstance::kMlDsa65:
      switch (classical_algorithm) {
        case ClassicalAlgorithm::kEd25519:
        case ClassicalAlgorithm::kEcdsaP256:
        case ClassicalAlgorithm::kEcdsaP384:
        case ClassicalAlgorithm::kRsa3072Pss:
        case ClassicalAlgorithm::kRsa4096Pss:
        case ClassicalAlgorithm::kRsa3072Pkcs1:
        case ClassicalAlgorithm::kRsa4096Pkcs1:
          break;
        default:
          return absl::Status(absl::StatusCode::kInvalidArgument,
                              "Unsupported classical algorithm for ML-DSA-65.");
      }
      break;
    case MlDsaInstance::kMlDsa87:
      switch (classical_algorithm) {
        case ClassicalAlgorithm::kEcdsaP384:
        case ClassicalAlgorithm::kEcdsaP521:
        case ClassicalAlgorithm::kRsa3072Pss:
        case ClassicalAlgorithm::kRsa4096Pss:
          break;
        default:
          return absl::Status(absl::StatusCode::kInvalidArgument,
                              "Unsupported classical algorithm for ML-DSA-87.");
      }
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unsupported ML-DSA instance.");
  }

  if (variant != Variant::kTink && variant != Variant::kNoPrefix) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create composite ML-DSA parameters with unknown Variant.");
  }

  return CompositeMlDsaParameters(ml_dsa_instance, classical_algorithm,
                                  variant);
}

bool CompositeMlDsaParameters::operator==(const Parameters& other) const {
  const CompositeMlDsaParameters* other_composite_mldsa_parameters =
      dynamic_cast<const CompositeMlDsaParameters*>(&other);
  if (other_composite_mldsa_parameters == nullptr) return false;
  return ml_dsa_instance_ ==
             other_composite_mldsa_parameters->ml_dsa_instance_ &&
         classical_algorithm_ ==
             other_composite_mldsa_parameters->classical_algorithm_ &&
         variant_ == other_composite_mldsa_parameters->variant_;
}

}  // namespace tink
}  // namespace crypto
