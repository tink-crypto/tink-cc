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

#ifndef TINK_JWT_JWT_ML_DSA_PRIVATE_KEY_H_
#define TINK_JWT_JWT_ML_DSA_PRIVATE_KEY_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/jwt/jwt_ml_dsa_public_key.h"
#include "tink/jwt/jwt_signature_private_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {

// Represents a JWT ML-DSA private key to sign a JWT using ML-DSA.
class JwtMlDsaPrivateKey : public JwtSignaturePrivateKey {
 public:
  // Copyable and movable.
  JwtMlDsaPrivateKey(const JwtMlDsaPrivateKey& other)
      : public_key_(other.public_key_),
        private_seed_bytes_(other.private_seed_bytes_) {}

  JwtMlDsaPrivateKey& operator=(const JwtMlDsaPrivateKey& other) {
    if (this == &other) {
      return *this;
    }

    public_key_ = other.public_key_;
    private_seed_bytes_ = other.private_seed_bytes_;
    return *this;
  }

  JwtMlDsaPrivateKey(JwtMlDsaPrivateKey&& other) = default;
  JwtMlDsaPrivateKey& operator=(JwtMlDsaPrivateKey&& other) = default;

  static absl::StatusOr<JwtMlDsaPrivateKey> Create(
      const JwtMlDsaPublicKey& public_key,
      const RestrictedData& private_seed_bytes, PartialKeyAccessToken token);

  const RestrictedData& GetPrivateSeedBytes(PartialKeyAccessToken token) const {
    return private_seed_bytes_;
  }

  const JwtMlDsaPublicKey& GetPublicKey() const override { return public_key_; }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<JwtMlDsaPrivateKey>(*this);
  }

 private:
  explicit JwtMlDsaPrivateKey(const JwtMlDsaPublicKey& public_key,
                              const RestrictedData& private_seed_bytes)
      : public_key_(public_key), private_seed_bytes_(private_seed_bytes) {}

  JwtMlDsaPublicKey public_key_;
  RestrictedData private_seed_bytes_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_ML_DSA_PRIVATE_KEY_H_
