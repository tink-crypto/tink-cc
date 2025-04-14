// Copyright 2025 Google LLC
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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_KEM_CECPQ2_PRIVATE_KEY_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_KEM_CECPQ2_PRIVATE_KEY_H_

#include <memory>

#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_public_key.h"
#include "tink/hybrid/hybrid_private_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {

// Representation of the decryption function of a CECPQ2 hybrid encryption
// primitive.
class Cecpq2PrivateKey final : public HybridPrivateKey {
 public:
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    Builder() = default;

    Builder& SetPublicKey(const Cecpq2PublicKey& public_key);
    Builder& SetX25519PrivateKeyBytes(
        const RestrictedData& x25519_private_key_bytes);
    Builder& SetHrssPrivateKeySeed(
        const RestrictedData& hrss_private_key_seed);

    absl::StatusOr<Cecpq2PrivateKey> Build(PartialKeyAccessToken token);

   private:
    absl::optional<Cecpq2PublicKey> public_key_;
    absl::optional<RestrictedData> x25519_private_key_bytes_;
    absl::optional<RestrictedData> hrss_private_key_seed_;
  };

  // Copyable and movable.
  Cecpq2PrivateKey(const Cecpq2PrivateKey& other) = default;
  Cecpq2PrivateKey& operator=(const Cecpq2PrivateKey& other) = default;
  Cecpq2PrivateKey(Cecpq2PrivateKey&& other) = default;
  Cecpq2PrivateKey& operator=(Cecpq2PrivateKey&& other) = default;

  const Cecpq2PublicKey& GetPublicKey() const override { return public_key_; }

  const RestrictedData& GetX25519PrivateKeyBytes(
      PartialKeyAccessToken token) const {
    return x25519_private_key_bytes_;
  }

  const RestrictedData& GetHrssPrivateKeySeed(
      PartialKeyAccessToken token) const {
    return hrss_private_key_seed_;
  }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<Cecpq2PrivateKey>(*this);
  }

 private:
  // Creates a CECPQ2 private key.
  explicit Cecpq2PrivateKey(const Cecpq2PublicKey& public_key,
                            const RestrictedData& x25519_private_key_bytes,
                            const RestrictedData& hrss_private_key_seed)
      : public_key_(public_key),
        x25519_private_key_bytes_(x25519_private_key_bytes),
        hrss_private_key_seed_(hrss_private_key_seed) {}

  Cecpq2PublicKey public_key_;
  RestrictedData x25519_private_key_bytes_;
  RestrictedData hrss_private_key_seed_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_KEM_CECPQ2_PRIVATE_KEY_H_
