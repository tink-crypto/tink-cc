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

#ifndef TINK_SIGNATURE_COMPOSITE_ML_DSA_PARAMETERS_H_
#define TINK_SIGNATURE_COMPOSITE_ML_DSA_PARAMETERS_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/parameters.h"
#include "tink/signature/signature_parameters.h"

namespace crypto {
namespace tink {

class CompositeMlDsaParameters : public SignatureParameters {
 public:
  // Describes the output prefix prepended to the signature.
  enum class Variant : int {
    // Prepends '0x01<big endian key id>' to signature.
    kTink = 1,
    // Does not prepend any prefix (i.e., keys must have no ID requirement).
    kNoPrefix = 2,
    // Added to guard from failures that may be caused by future expansions.
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Description of the ML-DSA instance. Only ML-DSA-65 and ML-DSA-87 are
  // supported at the moment.
  enum class MlDsaInstance : int {
    kMlDsa65 = 1,
    kMlDsa87 = 2,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Description of the classical algorithm. Only the following algorithms are
  // supported at the moment:
  //
  // - Ed25519
  // - ECDSA with P256, P384, and P521
  // - RSA-PSS with 3072 and 4096 bit keys
  // - RSA-PKCS1 with 3072 and 4096 bit keys
  enum class ClassicalAlgorithm : int {
    kEd25519 = 1,
    kEcdsaP256 = 2,
    kEcdsaP384 = 3,
    kEcdsaP521 = 4,
    kRsa3072Pss = 5,
    kRsa4096Pss = 6,
    kRsa3072Pkcs1 = 7,
    kRsa4096Pkcs1 = 8,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  static absl::StatusOr<CompositeMlDsaParameters> Create(
      MlDsaInstance ml_dsa_instance, ClassicalAlgorithm classical_algorithm,
      Variant variant);

  // Copyable and movable.
  CompositeMlDsaParameters(const CompositeMlDsaParameters& other) = default;
  CompositeMlDsaParameters& operator=(const CompositeMlDsaParameters& other) =
      default;
  CompositeMlDsaParameters(CompositeMlDsaParameters&& other) = default;
  CompositeMlDsaParameters& operator=(CompositeMlDsaParameters&& other) =
      default;

  MlDsaInstance GetMlDsaInstance() const { return ml_dsa_instance_; }
  ClassicalAlgorithm GetClassicalAlgorithm() const {
    return classical_algorithm_;
  }
  Variant GetVariant() const { return variant_; }

  bool HasIdRequirement() const override { return variant_ == Variant::kTink; }

  bool operator==(const Parameters& other) const override;

  std::unique_ptr<Parameters> Clone() const override {
    return std::make_unique<CompositeMlDsaParameters>(*this);
  }

 private:
  explicit CompositeMlDsaParameters(MlDsaInstance ml_dsa_instance,
                                    ClassicalAlgorithm classical_algorithm,
                                    Variant variant)
      : ml_dsa_instance_(ml_dsa_instance),
        classical_algorithm_(classical_algorithm),
        variant_(variant) {}

  MlDsaInstance ml_dsa_instance_;
  ClassicalAlgorithm classical_algorithm_;
  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_COMPOSITE_ML_DSA_PARAMETERS_H_
