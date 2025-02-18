// Copyright 2024 Google LLC
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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_KEM_ML_KEM_PARAMETERS_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_KEM_ML_KEM_PARAMETERS_H_

#include <memory>

#include "tink/experimental/kem/kem_parameters.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Representation of the parameters sets for the Module-Lattice-Based
// Key-Encapsulation Mechanism Standard (ML-KEM) described at
// https://csrc.nist.gov/pubs/fips/203/ipd.
//
// Note that only the ML-KEM-768 parameter set is currently supported.
class MlKemParameters : public KemParameters {
 public:
  // Describes the output prefix prepended to the encapsulation.
  //
  // Note: a Tink prefix is currently required for KEMs.
  enum class Variant : int {
    // Prepends '0x01<big endian key id>' to the encapsulation.
    kTink = 1,
    // Added to guard from failures that may be caused by future expansions.
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Copyable and movable.
  MlKemParameters(const MlKemParameters& other) = default;
  MlKemParameters& operator=(const MlKemParameters& other) = default;
  MlKemParameters(MlKemParameters&& other) = default;
  MlKemParameters& operator=(MlKemParameters&& other) = default;

  // Creates ML-KEM parameters instances. The possible key sizes are 512, 768
  // and 1024, but only 768 is supported at the moment.
  static absl::StatusOr<MlKemParameters> Create(int key_size, Variant variant);

  // Returns the ML-KEM key size (512, 768 or 1024). Only 768 is supported at
  // the moment.
  int GetKeySize() const { return key_size_; }
  Variant GetVariant() const { return variant_; }

  bool HasIdRequirement() const override { return variant_ == Variant::kTink; }

  bool operator==(const Parameters& other) const override;

  std::unique_ptr<Parameters> Clone() const override {
    return std::make_unique<MlKemParameters>(*this);
  }

 private:
  explicit MlKemParameters(int key_size, Variant variant)
      : key_size_(key_size), variant_(variant) {}

  int key_size_;
  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_KEM_ML_KEM_PARAMETERS_H_
