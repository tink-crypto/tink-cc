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

#ifndef TINK_SIGNATURE_ML_DSA_PARAMETERS_H_
#define TINK_SIGNATURE_ML_DSA_PARAMETERS_H_

#include "tink/parameters.h"
#include "tink/signature/signature_parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Representation of the parameters sets for the Module-Lattice Digital
// Signature Standard (ML-DSA) described at
// https://csrc.nist.gov/pubs/fips/204/ipd.
//
// Note that only the ML-DSA-65 parameter set is currently supported.
class MlDsaParameters : public SignatureParameters {
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

  // Description of the ML-DSA instance. Only ML-DSA-65 is supported at
  // the moment.
  enum class Instance : int {
    kMlDsa65 = 1,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Copyable and movable.
  MlDsaParameters(const MlDsaParameters& other) = default;
  MlDsaParameters& operator=(const MlDsaParameters& other) = default;
  MlDsaParameters(MlDsaParameters&& other) = default;
  MlDsaParameters& operator=(MlDsaParameters&& other) = default;

  // Creates ML-DSA parameters instances.
  static util::StatusOr<MlDsaParameters> Create(Instance instance,
                                                Variant variant);

  // Returns the ML-DSA key instance (44, 65 or 87). Only 65 is supported at
  // the moment.
  Instance GetInstance() const { return instance_; }
  Variant GetVariant() const { return variant_; }

  bool HasIdRequirement() const override { return variant_ == Variant::kTink; }

  bool operator==(const Parameters& other) const override;

 private:
  explicit MlDsaParameters(Instance instance, Variant variant)
      : instance_(instance), variant_(variant) {}

  Instance instance_;
  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_ML_DSA_PARAMETERS_H_
