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

#include "tink/subtle/ed25519_sign_boringssl.h"

#include <memory>
#include <optional>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/restricted_data.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/internal/ed25519_sign_boringssl.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {

// static
absl::StatusOr<std::unique_ptr<PublicKeySign>> Ed25519SignBoringSsl::New(
    SecretData private_key) {
  ABSL_RETURN_IF_ERROR(
      internal::CheckFipsCompatibility<Ed25519SignBoringSsl>());
  // OpenSSL/BoringSSL consider the ED25519's private key to be: private_key ||
  // public_key.
  const int kSslPrivateKeySize =
      internal::Ed25519KeyPrivKeySize() + internal::Ed25519KeyPubKeySize();
  if (private_key.size() != kSslPrivateKeySize) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("Invalid ED25519 private key size (%d). "
                        "The only valid size is %d.",
                        private_key.size(), kSslPrivateKeySize));
  }
  ABSL_ASSIGN_OR_RETURN(
      Ed25519Parameters parameters,
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix));
  ABSL_ASSIGN_OR_RETURN(
      Ed25519PrivateKey key,
      Ed25519PrivateKey::Create(
          parameters,
          RestrictedData(private_key.AsStringView().substr(
                             0, internal::Ed25519KeyPrivKeySize()),
                         InsecureSecretKeyAccess::Get()),
          /*id_requirement=*/std::nullopt, GetPartialKeyAccess()));
  return internal::NewEd25519SignBoringSsl(key);
}

absl::StatusOr<std::unique_ptr<PublicKeySign>> Ed25519SignBoringSsl::New(
    const Ed25519PrivateKey& key) {
  return internal::NewEd25519SignBoringSsl(key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
