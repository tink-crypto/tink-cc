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

#ifndef TINK_AEAD_X_AES_GCM_PARAMETERS_H_
#define TINK_AEAD_X_AES_GCM_PARAMETERS_H_

#include "tink/aead/aead_parameters.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Describes the parameters of an `XAesGcmKey`.
class XAesGcmParameters : public AeadParameters {
 public:
  // Description of the output prefix prepended to the ciphertext.
  enum class Variant : int {
    // Prepends '0x01<big endian key id>' to the ciphertext.
    kTink = 1,
    // Does not prepend any prefix (i.e., keys must have no ID requirement).
    kNoPrefix = 2,
    // Added to guard from failures that may be caused by future expansions.
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Copyable and movable.
  XAesGcmParameters(const XAesGcmParameters& other) = default;
  XAesGcmParameters& operator=(const XAesGcmParameters& other) = default;
  XAesGcmParameters(XAesGcmParameters&& other) = default;
  XAesGcmParameters& operator=(XAesGcmParameters&& other) = default;

  static util::StatusOr<XAesGcmParameters> Create(Variant variant,
                                                  int salt_size_bytes);

  Variant GetVariant() const { return variant_; }

  int SaltSizeBytes() const { return salt_size_bytes_; }

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

 private:
  XAesGcmParameters(Variant variant, int salt_size_bytes)
      : variant_(variant), salt_size_bytes_(salt_size_bytes) {}

  Variant variant_;
  int salt_size_bytes_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_X_AES_GCM_PARAMETERS_H_
