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
////////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/jwt_ml_dsa_private_key.h"

#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "openssl/mldsa.h"
#include "tink/jwt/jwt_ml_dsa_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/signature/ml_dsa_private_key.h"

namespace crypto {
namespace tink {

absl::StatusOr<JwtMlDsaPrivateKey> JwtMlDsaPrivateKey::Create(
    const JwtMlDsaPublicKey& public_key,
    const RestrictedData& private_seed_bytes, PartialKeyAccessToken token) {
  if (private_seed_bytes.size() != MLDSA_SEED_BYTES) {
    return absl::InvalidArgumentError(
        absl::StrCat("Private key length ", private_seed_bytes.size(),
                     " is different from expected length ", MLDSA_SEED_BYTES));
  }

  ABSL_ASSIGN_OR_RETURN(
      MlDsaPrivateKey ml_dsa_private_key,
      MlDsaPrivateKey::Create(public_key.GetMlDsaPublicKey(token),
                              private_seed_bytes, token));

  return JwtMlDsaPrivateKey(public_key, std::move(ml_dsa_private_key));
}

bool JwtMlDsaPrivateKey::operator==(const Key& other) const {
  const JwtMlDsaPrivateKey* that =
      dynamic_cast<const JwtMlDsaPrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return public_key_ == that->public_key_ &&
         ml_dsa_private_key_ == that->ml_dsa_private_key_;
}

}  // namespace tink
}  // namespace crypto
