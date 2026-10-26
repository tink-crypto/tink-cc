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

#include "tink/jwt/jwt_ecdsa_private_key.h"

#include <utility>

#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/signature/ecdsa_private_key.h"

namespace crypto {
namespace tink {

absl::StatusOr<JwtEcdsaPrivateKey> JwtEcdsaPrivateKey::Create(
    const JwtEcdsaPublicKey& public_key,
    const RestrictedData& private_key_value, PartialKeyAccessToken token) {
  ABSL_ASSIGN_OR_RETURN(
      EcdsaPrivateKey ecdsa_private_key,
      EcdsaPrivateKey::Create(public_key.GetEcdsaPublicKey(token),
                              private_key_value, token));
  return JwtEcdsaPrivateKey(public_key, std::move(ecdsa_private_key));
}

absl::StatusOr<JwtEcdsaPrivateKey>
JwtEcdsaPrivateKey::CreateAllowNonConstantTime(
    const JwtEcdsaPublicKey& public_key,
    const RestrictedData& private_key_value, PartialKeyAccessToken token) {
  ABSL_ASSIGN_OR_RETURN(
      EcdsaPrivateKey ecdsa_private_key,
      EcdsaPrivateKey::CreateAllowNonConstantTime(
          public_key.GetEcdsaPublicKey(token), private_key_value, token));
  return JwtEcdsaPrivateKey(public_key, std::move(ecdsa_private_key));
}

bool JwtEcdsaPrivateKey::operator==(const Key& other) const {
  const JwtEcdsaPrivateKey* that =
      dynamic_cast<const JwtEcdsaPrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return public_key_ == that->public_key_ &&
         ecdsa_private_key_ == that->ecdsa_private_key_;
}

}  // namespace tink
}  // namespace crypto
