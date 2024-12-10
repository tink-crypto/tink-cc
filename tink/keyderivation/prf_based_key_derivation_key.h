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

#ifndef TINK_KEYDERIVATION_PRF_BASED_KEY_DERIVATION_KEY_H_
#define TINK_KEYDERIVATION_PRF_BASED_KEY_DERIVATION_KEY_H_

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/types/optional.h"
#include "tink/key.h"
#include "tink/keyderivation/key_derivation_key.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"
#include "tink/partial_key_access_token.h"
#include "tink/prf/prf_key.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Represents a PRF-based key derivation.
class PrfBasedKeyDerivationKey : public KeyDerivationKey {
 public:
  // Copyable and movable.
  PrfBasedKeyDerivationKey(const PrfBasedKeyDerivationKey& other) = default;
  PrfBasedKeyDerivationKey& operator=(const PrfBasedKeyDerivationKey& other) =
      default;
  PrfBasedKeyDerivationKey(PrfBasedKeyDerivationKey&& other) = default;
  PrfBasedKeyDerivationKey& operator=(PrfBasedKeyDerivationKey&& other) =
      default;

  static util::StatusOr<PrfBasedKeyDerivationKey> Create(
      const PrfBasedKeyDerivationParameters& parameters, const PrfKey& prf_key,
      absl::optional<int> id_requirement, PartialKeyAccessToken token);

  const PrfKey& GetPrfKey() const { return *prf_key_; }

  const PrfBasedKeyDerivationParameters& GetParameters() const override {
    return *parameters_;
  }

  absl::optional<int32_t> GetIdRequirement() const override {
    return id_requirement_;
  }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<PrfBasedKeyDerivationKey>(*this);
  }

 private:
  PrfBasedKeyDerivationKey(
      std::unique_ptr<const PrfBasedKeyDerivationParameters> parameters,
      std::unique_ptr<const PrfKey> prf_key, absl::optional<int> id_requirement)
      : parameters_(std::move(parameters)),
        prf_key_(std::move(prf_key)),
        id_requirement_(id_requirement) {}

  std::shared_ptr<const PrfBasedKeyDerivationParameters> parameters_;
  std::shared_ptr<const PrfKey> prf_key_;
  absl::optional<int> id_requirement_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYDERIVATION_PRF_BASED_KEY_DERIVATION_KEY_H_
