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

#ifndef TINK_JWT_JWT_ECDSA_PRIVATE_KEY_H_
#define TINK_JWT_JWT_ECDSA_PRIVATE_KEY_H_

#include <memory>

#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/jwt/jwt_signature_private_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_big_integer.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Represents a JWT ECDSA private key to sign a JWT using ECDSA.
class JwtEcdsaPrivateKey : public JwtSignaturePrivateKey {
 public:
  // Copyable and movable.
  JwtEcdsaPrivateKey(const JwtEcdsaPrivateKey& other) = default;
  JwtEcdsaPrivateKey& operator=(const JwtEcdsaPrivateKey& other) = default;
  JwtEcdsaPrivateKey(JwtEcdsaPrivateKey&& other) = default;
  JwtEcdsaPrivateKey& operator=(JwtEcdsaPrivateKey&& other) = default;

  static util::StatusOr<JwtEcdsaPrivateKey> Create(
      const JwtEcdsaPublicKey& public_key,
      const RestrictedBigInteger& private_key_value,
      PartialKeyAccessToken token);

  const RestrictedBigInteger& GetPrivateKeyValue(
      PartialKeyAccessToken token) const {
    return private_key_value_;
  }

  const JwtEcdsaPublicKey& GetPublicKey() const override { return public_key_; }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<JwtEcdsaPrivateKey>(*this);
  }

 private:
  explicit JwtEcdsaPrivateKey(const JwtEcdsaPublicKey& public_key,
                              const RestrictedBigInteger& private_key_value)
      : public_key_(public_key), private_key_value_(private_key_value) {}

  JwtEcdsaPublicKey public_key_;
  RestrictedBigInteger private_key_value_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_ECDSA_PRIVATE_KEY_H_
