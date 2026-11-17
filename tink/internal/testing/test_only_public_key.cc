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

#include "tink/internal/testing/test_only_public_key.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/testing/test_only_asymmetric_parameters.h"
#include "tink/internal/testing/test_only_key.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/public_key_verify.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<TestOnlyPublicKey> TestOnlyPublicKey::Create(
    const TestOnlyAsymmetricParameters& parameters,
    absl::string_view public_key_bytes, absl::optional<int> id_requirement,
    PartialKeyAccessToken token) {
  ABSL_ASSIGN_OR_RETURN(
      std::string output_prefix,
      ComputeTestOnlyOutputPrefix(parameters.GetVariant(), id_requirement));
  return TestOnlyPublicKey(parameters, public_key_bytes, id_requirement,
                           std::move(output_prefix));
}

bool TestOnlyPublicKey::operator==(const Key& other) const {
  const TestOnlyPublicKey* that =
      dynamic_cast<const TestOnlyPublicKey*>(&other);
  return that != nullptr && parameters_ == that->parameters_ &&
         public_key_bytes_ == that->public_key_bytes_ &&
         id_requirement_ == that->id_requirement_;
}

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> NewTestOnlyPublicKeyVerify(
    const TestOnlyPublicKey& key) {
  return {std::make_unique<test::DummyPublicKeyVerify>(
      absl::BytesToHexString(key.GetPublicKeyBytes(GetPartialKeyAccess())))};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
