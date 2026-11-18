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

#ifndef TINK_INTERNAL_TESTING_TEST_ONLY_PRIVATE_KEY_H_
#define TINK_INTERNAL_TESTING_TEST_ONLY_PRIVATE_KEY_H_

#include <cstdint>
#include <memory>

#include "absl/base/attributes.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/testing/test_only_asymmetric_parameters.h"
#include "tink/internal/testing/test_only_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/private_key.h"
#include "tink/public_key_sign.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {
namespace internal {

// A test-only private key. The key material of its public key is its reversed
// key material.
class TestOnlyPrivateKey final : public PrivateKey {
 public:
  // Copyable and movable.
  TestOnlyPrivateKey(const TestOnlyPrivateKey& other) = default;
  TestOnlyPrivateKey& operator=(const TestOnlyPrivateKey& other) = default;
  TestOnlyPrivateKey(TestOnlyPrivateKey&& other) = default;
  TestOnlyPrivateKey& operator=(TestOnlyPrivateKey&& other) = default;

  // Returns an error if the key material of `public_key` isn't the reversed
  // `private_key_bytes`.
  static absl::StatusOr<TestOnlyPrivateKey> Create(
      const TestOnlyPublicKey& public_key,
      const RestrictedData& private_key_bytes, PartialKeyAccessToken token);

  // Creates a private key from `private_key_bytes`, which can have any size,
  // and computes its public key. Returns an error if `id_requirement` doesn't
  // match `parameters.HasIdRequirement()`.
  static absl::StatusOr<TestOnlyPrivateKey> Create(
      const TestOnlyAsymmetricParameters& parameters,
      const RestrictedData& private_key_bytes,
      absl::optional<int> id_requirement, PartialKeyAccessToken token);

  const RestrictedData& GetPrivateKeyBytes(PartialKeyAccessToken token) const
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return private_key_bytes_;
  }

  absl::string_view GetOutputPrefix() const ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return public_key_.GetOutputPrefix();
  }

  const TestOnlyPublicKey& GetPublicKey() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND override {
    return public_key_;
  }

  const TestOnlyAsymmetricParameters& GetParameters() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND override {
    return public_key_.GetParameters();
  }

  absl::optional<int32_t> GetIdRequirement() const override {
    return public_key_.GetIdRequirement();
  }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<TestOnlyPrivateKey>(*this);
  }

 private:
  TestOnlyPrivateKey(const TestOnlyPublicKey& public_key,
                     const RestrictedData& private_key_bytes)
      : public_key_(public_key), private_key_bytes_(private_key_bytes) {}

  TestOnlyPublicKey public_key_;
  RestrictedData private_key_bytes_;
};

// Creates a `TestOnlyPrivateKey` with random key material of
// `kTestOnlyKeySizeInBytes` bytes. Can be added to a `KeyGenConfiguration`
// with `KeyGenConfigurationImpl::AddKeyCreator<TestOnlyAsymmetricParameters>`.
absl::StatusOr<std::unique_ptr<Key>> CreateTestOnlyPrivateKey(
    const TestOnlyAsymmetricParameters& parameters,
    absl::optional<int> id_requirement);

// Returns a `test::DummyPublicKeySign` for `key`, whose signatures are
// verified by the `NewTestOnlyPublicKeyVerify` primitive of its public key.
// Can be added to a `Configuration` with
// `ConfigurationImpl::AddPrimitiveGetter<PublicKeySign, TestOnlyPrivateKey>`.
//
// The primitive is compatible with the `PublicKeySign` primitives of
// `TestOnlyPrivateKeyTypeManager` (in `test_only_key_managers.h`).
absl::StatusOr<std::unique_ptr<PublicKeySign>> NewTestOnlyPublicKeySign(
    const TestOnlyPrivateKey& key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_TESTING_TEST_ONLY_PRIVATE_KEY_H_
