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

#ifndef TINK_INTERNAL_TESTING_TEST_ONLY_PUBLIC_KEY_H_
#define TINK_INTERNAL_TESTING_TEST_ONLY_PUBLIC_KEY_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/testing/test_only_asymmetric_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/public_key_verify.h"

namespace crypto {
namespace tink {
namespace internal {

// A test-only public key.
class TestOnlyPublicKey final : public Key {
 public:
  // Copyable and movable.
  TestOnlyPublicKey(const TestOnlyPublicKey& other) = default;
  TestOnlyPublicKey& operator=(const TestOnlyPublicKey& other) = default;
  TestOnlyPublicKey(TestOnlyPublicKey&& other) = default;
  TestOnlyPublicKey& operator=(TestOnlyPublicKey&& other) = default;

  // Returns an error if `id_requirement` doesn't match
  // `parameters.HasIdRequirement()`. `public_key_bytes` can have any size.
  static absl::StatusOr<TestOnlyPublicKey> Create(
      const TestOnlyAsymmetricParameters& parameters,
      absl::string_view public_key_bytes, absl::optional<int> id_requirement,
      PartialKeyAccessToken token);

  absl::string_view GetPublicKeyBytes(PartialKeyAccessToken token) const
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return public_key_bytes_;
  }

  absl::string_view GetOutputPrefix() const ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return output_prefix_;
  }

  const TestOnlyAsymmetricParameters& GetParameters() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND override {
    return parameters_;
  }

  absl::optional<int32_t> GetIdRequirement() const override {
    return id_requirement_;
  }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<TestOnlyPublicKey>(*this);
  }

 private:
  TestOnlyPublicKey(const TestOnlyAsymmetricParameters& parameters,
                    absl::string_view public_key_bytes,
                    absl::optional<int> id_requirement,
                    std::string output_prefix)
      : parameters_(parameters),
        public_key_bytes_(public_key_bytes),
        id_requirement_(id_requirement),
        output_prefix_(std::move(output_prefix)) {}

  TestOnlyAsymmetricParameters parameters_;
  std::string public_key_bytes_;
  absl::optional<int> id_requirement_;
  std::string output_prefix_;
};

// Returns a `test::DummyPublicKeyVerify` for `key`. Can be added to a
// `Configuration` with
// `ConfigurationImpl::AddPrimitiveGetter<PublicKeyVerify, TestOnlyPublicKey>`.
//
// The primitive is compatible with the `PublicKeyVerify` primitives of
// `TestOnlyPublicKeyTypeManager` (in `test_only_key_managers.h`).
absl::StatusOr<std::unique_ptr<PublicKeyVerify>> NewTestOnlyPublicKeyVerify(
    const TestOnlyPublicKey& key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_TESTING_TEST_ONLY_PUBLIC_KEY_H_
