// Copyright 2025 Google LLC
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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_KEM_CECPQ2_PARAMETERS_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_KEM_CECPQ2_PARAMETERS_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/hybrid/hybrid_parameters.h"
#include "tink/parameters.h"

namespace crypto {
namespace tink {

// Representation of CECPQ2 hybrid encryption parameters.
// https://blog.cloudflare.com/the-tls-post-quantum-experiment
class Cecpq2Parameters : public HybridParameters {
 public:
  // Description of the output prefix prepended to the ciphertext.
  enum class Variant : int {
    // Prepends '0x01<big endian key id>' to ciphertext.
    kTink = 1,
    // Does not prepend any prefix (i.e., keys must have no ID requirement).
    kNoPrefix = 2,
    // Added to guard from failures that may be caused by future expansions.
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Copyable and movable.
  Cecpq2Parameters(const Cecpq2Parameters& other) = default;
  Cecpq2Parameters& operator=(const Cecpq2Parameters& other) = default;
  Cecpq2Parameters(Cecpq2Parameters&& other) = default;
  Cecpq2Parameters& operator=(Cecpq2Parameters&& other) = default;

  // Returns an error status if the variant specified in `dem_parameters` is
  // anything other than a no-prefix variant.
  static absl::StatusOr<Cecpq2Parameters> Create(
      const Parameters& dem_parameters, absl::optional<absl::string_view> salt,
      Variant variant);

  const Parameters& GetDemParameters() const { return *dem_parameters_; }

  absl::optional<absl::string_view> GetSalt() const { return salt_; }

  Variant GetVariant() const { return variant_; }

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

  std::unique_ptr<Parameters> Clone() const override {
    return std::make_unique<Cecpq2Parameters>(*this);
  }

 private:
  explicit Cecpq2Parameters(std::unique_ptr<const Parameters> dem_parameters,
                            absl::optional<absl::string_view> salt,
                            Variant variant)
      : dem_parameters_(std::move(dem_parameters)),
        salt_(salt),
        variant_(variant) {}

  std::shared_ptr<const Parameters> dem_parameters_;
  absl::optional<std::string> salt_ = absl::nullopt;
  Variant variant_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_KEM_CECPQ2_PARAMETERS_H_
