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

#ifndef TINK_KEYDERIVATION_PRF_BASED_KEY_DERIVATION_PARAMETERS_H_
#define TINK_KEYDERIVATION_PRF_BASED_KEY_DERIVATION_PARAMETERS_H_

#include <memory>
#include <utility>

#include "absl/memory/memory.h"
#include "tink/keyderivation/key_derivation_parameters.h"
#include "tink/parameters.h"
#include "tink/prf/prf_parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

class PrfBasedKeyDerivationParameters : public KeyDerivationParameters {
 public:
  class Builder {
   public:
    // Movable, but not copyable.
    Builder(const Builder& other) = delete;
    Builder& operator=(const Builder& other) = delete;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty parameters builder.
    Builder() = default;

    Builder& SetPrfParameters(const PrfParameters& prf_parameters);
    Builder& SetDerivedKeyParameters(const Parameters& derived_key_parameters);

    absl::StatusOr<PrfBasedKeyDerivationParameters> Build();

   private:
    std::unique_ptr<const Parameters> prf_parameters_;
    std::unique_ptr<const Parameters> derived_key_parameters_;
  };

  // Copyable and movable.
  PrfBasedKeyDerivationParameters(
      const PrfBasedKeyDerivationParameters& other) = default;
  PrfBasedKeyDerivationParameters& operator=(
      const PrfBasedKeyDerivationParameters& other) = default;
  PrfBasedKeyDerivationParameters(PrfBasedKeyDerivationParameters&& other) =
      default;
  PrfBasedKeyDerivationParameters& operator=(
      PrfBasedKeyDerivationParameters&& other) = default;

  const PrfParameters& GetPrfParameters() const { return *prf_parameters_; }

  const Parameters& GetDerivedKeyParameters() const override {
    return *derived_key_parameters_;
  }

  std::unique_ptr<Parameters> Clone() const override {
    return absl::make_unique<PrfBasedKeyDerivationParameters>(*this);
  }

  bool operator==(const Parameters& other) const override;

 private:
  explicit PrfBasedKeyDerivationParameters(
      std::unique_ptr<const PrfParameters> prf_parameters,
      std::unique_ptr<const Parameters> derived_key_parameters)
      : prf_parameters_(std::move(prf_parameters)),
        derived_key_parameters_(std::move(derived_key_parameters)) {}

  std::shared_ptr<const PrfParameters> prf_parameters_;
  std::shared_ptr<const Parameters> derived_key_parameters_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYDERIVATION_PRF_BASED_KEY_DERIVATION_PARAMETERS_H_
