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

#ifndef TINK_AEAD_CHACHA20_POLY1305_PARAMETERS_H_
#define TINK_AEAD_CHACHA20_POLY1305_PARAMETERS_H_

#include <memory>

#include "tink/aead/aead_parameters.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Describes the parameters of a `ChaCha20Poly1305Key`.
class ChaCha20Poly1305Parameters : public AeadParameters {
 public:
  // Description of the output prefix prepended to the ciphertext.
  enum class Variant : int {
    // Prepends '0x01<big endian key id>' to the ciphertext.
    kTink = 1,
    // Prepends '0x00<big endian key id>' to the ciphertext.
    kCrunchy = 2,
    // Does not prepend any prefix (i.e., keys must have no ID requirement).
    kNoPrefix = 3,
    // Added to guard from failures that may be caused by future expansions.
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Copyable and movable.
  ChaCha20Poly1305Parameters(const ChaCha20Poly1305Parameters& other) = default;
  ChaCha20Poly1305Parameters& operator=(
      const ChaCha20Poly1305Parameters& other) = default;
  ChaCha20Poly1305Parameters(ChaCha20Poly1305Parameters&& other) = default;
  ChaCha20Poly1305Parameters& operator=(ChaCha20Poly1305Parameters&& other) =
      default;

  // Creates a new ChaCha20-Poly1305 parameters object. Returns an error if
  // `variant` is invalid.
  static absl::StatusOr<ChaCha20Poly1305Parameters> Create(Variant variant);

  Variant GetVariant() const { return variant_; }

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

  std::unique_ptr<Parameters> Clone() const override {
    return std::make_unique<ChaCha20Poly1305Parameters>(*this);
  }

 private:
  explicit ChaCha20Poly1305Parameters(Variant variant) : variant_(variant) {}

  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_CHACHA20_POLY1305_PARAMETERS_H_
