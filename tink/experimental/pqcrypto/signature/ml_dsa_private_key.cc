// Copyright 2024 Google LLC
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

#include "tink/experimental/pqcrypto/signature/ml_dsa_private_key.h"

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#define OPENSSL_UNSTABLE_EXPERIMENTAL_DILITHIUM
#include "openssl/experimental/dilithium.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_parameters.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<MlDsaPrivateKey> MlDsaPrivateKey::Create(
    const MlDsaPublicKey& public_key, const RestrictedData& private_key_bytes,
    PartialKeyAccessToken token) {
  if (private_key_bytes.size() != DILITHIUM_PRIVATE_KEY_BYTES) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Invalid ML-DSA private key size. Only ",
                                     DILITHIUM_PRIVATE_KEY_BYTES,
                                     "-byte keys are currently supported."));
  }

  if (public_key.GetParameters().GetInstance() !=
      MlDsaParameters::Instance::kMlDsa65) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid ML-DSA instance. Only ML-DSA-65 is "
                        "currently supported.");
  }

  // TODO(guillaumee): Add a DILITHIUM_public_from_private() function and
  // confirm that the private key and public key are a valid ML-DSA key pair.

  return MlDsaPrivateKey(public_key, private_key_bytes);
}

bool MlDsaPrivateKey::operator==(const Key& other) const {
  const MlDsaPrivateKey* that = dynamic_cast<const MlDsaPrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return public_key_ == that->public_key_ &&
         private_key_bytes_ == that->private_key_bytes_;
}

}  // namespace tink
}  // namespace crypto
