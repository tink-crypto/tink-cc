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

#ifndef TINK_AEAD_LEGACY_KMS_AEAD_PARAMETERS_H_
#define TINK_AEAD_LEGACY_KMS_AEAD_PARAMETERS_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "tink/aead/aead_parameters.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Describes the parameters of a `LegacyKmsAeadKey`.
class LegacyKmsAeadParameters : public AeadParameters {
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
  LegacyKmsAeadParameters(const LegacyKmsAeadParameters& other) = default;
  LegacyKmsAeadParameters& operator=(const LegacyKmsAeadParameters& other) =
      default;
  LegacyKmsAeadParameters(LegacyKmsAeadParameters&& other) = default;
  LegacyKmsAeadParameters& operator=(LegacyKmsAeadParameters&& other) = default;

  static absl::StatusOr<LegacyKmsAeadParameters> Create(
      absl::string_view key_uri, Variant variant);

  const std::string& GetKeyUri() const { return key_uri_; }

  Variant GetVariant() const { return variant_; }

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

  std::unique_ptr<Parameters> Clone() const override {
    return std::make_unique<LegacyKmsAeadParameters>(*this);
  }

 private:
  explicit LegacyKmsAeadParameters(absl::string_view key_uri, Variant variant)
      : key_uri_(key_uri), variant_(variant) {}

  std::string key_uri_;
  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_LEGACY_KMS_AEAD_PARAMETERS_H_
