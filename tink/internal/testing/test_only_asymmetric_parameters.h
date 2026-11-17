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
///////////////////////////////////////////////////////////////////////////////

#ifndef TINK_INTERNAL_TESTING_TEST_ONLY_ASYMMETRIC_PARAMETERS_H_
#define TINK_INTERNAL_TESTING_TEST_ONLY_ASYMMETRIC_PARAMETERS_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/internal/testing/test_only_key.h"
#include "tink/parameters.h"

namespace crypto {
namespace tink {
namespace internal {

// Parameters of a `TestOnlyPrivateKey` and of its `TestOnlyPublicKey`.
class TestOnlyAsymmetricParameters final : public Parameters {
 public:
  // Output prefix of the keys, as for `TestOnlyParameters`.
  using Variant = TestOnlyParameters::Variant;

  // Copyable and movable.
  TestOnlyAsymmetricParameters(const TestOnlyAsymmetricParameters& other) =
      default;
  TestOnlyAsymmetricParameters& operator=(
      const TestOnlyAsymmetricParameters& other) = default;
  TestOnlyAsymmetricParameters(TestOnlyAsymmetricParameters&& other) = default;
  TestOnlyAsymmetricParameters& operator=(
      TestOnlyAsymmetricParameters&& other) = default;

  // Returns an error if `variant` is invalid.
  static absl::StatusOr<TestOnlyAsymmetricParameters> Create(Variant variant);

  Variant GetVariant() const { return variant_; }

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

  std::unique_ptr<Parameters> Clone() const override {
    return std::make_unique<TestOnlyAsymmetricParameters>(*this);
  }

 private:
  explicit TestOnlyAsymmetricParameters(Variant variant) : variant_(variant) {}

  Variant variant_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_TESTING_TEST_ONLY_ASYMMETRIC_PARAMETERS_H_
