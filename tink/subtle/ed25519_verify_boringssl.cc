// Copyright 2019 Google LLC
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

#include "tink/subtle/ed25519_verify_boringssl.h"

#include <memory>
#include <optional>

#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/signature/internal/ed25519_verify_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> Ed25519VerifyBoringSsl::New(
    const Ed25519PublicKey& public_key) {
  return internal::NewEd25519VerifyBoringSsl(public_key);
}

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> Ed25519VerifyBoringSsl::New(
    absl::string_view public_key) {
  ABSL_ASSIGN_OR_RETURN(
      Ed25519Parameters parameters,
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix));
  ABSL_ASSIGN_OR_RETURN(
      Ed25519PublicKey key,
      Ed25519PublicKey::Create(parameters, public_key,
                               /*id_requirement=*/std::nullopt,
                               GetPartialKeyAccess()));
  return internal::NewEd25519VerifyBoringSsl(key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
