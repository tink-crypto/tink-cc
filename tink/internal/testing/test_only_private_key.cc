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

#include "tink/internal/testing/test_only_private_key.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/testing/test_only_asymmetric_parameters.h"
#include "tink/internal/testing/test_only_key.h"
#include "tink/internal/testing/test_only_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/public_key_sign.h"
#include "tink/restricted_data.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

// The public key material is the reversed private key material.
std::string ComputePublicKeyBytes(const RestrictedData& private_key_bytes) {
  absl::string_view bytes =
      private_key_bytes.GetSecret(GetInsecureSecretKeyAccessInternal());
  return std::string(bytes.rbegin(), bytes.rend());
}

}  // namespace

absl::StatusOr<TestOnlyPrivateKey> TestOnlyPrivateKey::Create(
    const TestOnlyPublicKey& public_key,
    const RestrictedData& private_key_bytes, PartialKeyAccessToken token) {
  if (public_key.GetPublicKeyBytes(token) !=
      ComputePublicKeyBytes(private_key_bytes)) {
    return absl::InvalidArgumentError(
        "The public key doesn't match the private key");
  }
  return TestOnlyPrivateKey(public_key, private_key_bytes);
}

absl::StatusOr<TestOnlyPrivateKey> TestOnlyPrivateKey::Create(
    const TestOnlyAsymmetricParameters& parameters,
    const RestrictedData& private_key_bytes, absl::optional<int> id_requirement,
    PartialKeyAccessToken token) {
  ABSL_ASSIGN_OR_RETURN(
      TestOnlyPublicKey public_key,
      TestOnlyPublicKey::Create(parameters,
                                ComputePublicKeyBytes(private_key_bytes),
                                id_requirement, token));
  return TestOnlyPrivateKey(public_key, private_key_bytes);
}

bool TestOnlyPrivateKey::operator==(const Key& other) const {
  const TestOnlyPrivateKey* that =
      dynamic_cast<const TestOnlyPrivateKey*>(&other);
  return that != nullptr && public_key_ == that->public_key_ &&
         private_key_bytes_ == that->private_key_bytes_;
}

absl::StatusOr<std::unique_ptr<Key>> CreateTestOnlyPrivateKey(
    const TestOnlyAsymmetricParameters& parameters,
    absl::optional<int> id_requirement) {
  ABSL_ASSIGN_OR_RETURN(TestOnlyPrivateKey key,
                        TestOnlyPrivateKey::Create(
                            parameters, RestrictedData(kTestOnlyKeySizeInBytes),
                            id_requirement, GetPartialKeyAccess()));
  return {std::make_unique<TestOnlyPrivateKey>(std::move(key))};
}

absl::StatusOr<std::unique_ptr<PublicKeySign>> NewTestOnlyPublicKeySign(
    const TestOnlyPrivateKey& key) {
  return {std::make_unique<test::DummyPublicKeySign>(absl::BytesToHexString(
      key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess())))};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
