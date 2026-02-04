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

#include "absl/base/thread_annotations.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/jwt/jwt_signature_private_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {

// Represents a JWT ECDSA private key to sign a JWT using ECDSA.
class JwtEcdsaPrivateKey : public JwtSignaturePrivateKey {
 public:
  // Copyable and movable.
  JwtEcdsaPrivateKey(const JwtEcdsaPrivateKey& other)
      : public_key_(other.public_key_),
        private_key_value_(other.private_key_value_) {
    absl::MutexLock lock(other.mutex_);
    private_key_value_big_integer_ = other.private_key_value_big_integer_;
  }

  JwtEcdsaPrivateKey& operator=(const JwtEcdsaPrivateKey& other) {
    if (this == &other) {
      return *this;
    }

    absl::optional<RestrictedBigInteger> tmp_private_key_value_big_integer;
    {
      absl::MutexLock lock(other.mutex_);
      tmp_private_key_value_big_integer = other.private_key_value_big_integer_;
    }

    public_key_ = other.public_key_;
    private_key_value_ = other.private_key_value_;
    absl::MutexLock lock(mutex_);
    private_key_value_big_integer_ = tmp_private_key_value_big_integer;

    return *this;
  }

  JwtEcdsaPrivateKey(JwtEcdsaPrivateKey&& other) = default;
  JwtEcdsaPrivateKey& operator=(JwtEcdsaPrivateKey&& other) = default;

  static absl::StatusOr<JwtEcdsaPrivateKey> Create(
      const JwtEcdsaPublicKey& public_key,
      const RestrictedData& private_key_value, PartialKeyAccessToken token);

  // Pads private_key_value to GetPrivateKeyLength() if needed,
  // truncates leading zeros if needed.
  static absl::StatusOr<JwtEcdsaPrivateKey> CreateAllowNonConstantTime(
      const JwtEcdsaPublicKey& public_key,
      const RestrictedData& private_key_value, PartialKeyAccessToken token);

  // Deprecated. Will be removed in Tink 3.0.0. Please use the version taking
  // a `RestrictedData` object instead.
  static absl::StatusOr<JwtEcdsaPrivateKey> Create(
      const JwtEcdsaPublicKey& public_key,
      const RestrictedBigInteger& private_key_value,
      PartialKeyAccessToken token);

  const RestrictedData& GetPrivateKey(PartialKeyAccessToken token) const {
    return private_key_value_;
  }

  const RestrictedBigInteger& GetPrivateKeyValue(
      PartialKeyAccessToken token) const;

  const JwtEcdsaPublicKey& GetPublicKey() const override { return public_key_; }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<JwtEcdsaPrivateKey>(*this);
  }

 private:
  explicit JwtEcdsaPrivateKey(const JwtEcdsaPublicKey& public_key,
                              const RestrictedData& private_key_value)
      : public_key_(public_key), private_key_value_(private_key_value) {}

  JwtEcdsaPublicKey public_key_;
  RestrictedData private_key_value_;

  mutable absl::Mutex mutex_;
  mutable absl::optional<RestrictedBigInteger> private_key_value_big_integer_
      ABSL_GUARDED_BY(mutex_);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_ECDSA_PRIVATE_KEY_H_
