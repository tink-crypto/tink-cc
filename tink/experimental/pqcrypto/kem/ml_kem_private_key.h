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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_KEM_ML_KEM_PRIVATE_KEY_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_KEM_ML_KEM_PRIVATE_KEY_H_

#include <memory>

#include "absl/base/attributes.h"
#include "tink/experimental/kem/kem_private_key.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Representation of the decapsulation function for the ML-KEM key encapsulation
// mechanism primitive.
class MlKemPrivateKey : public KemPrivateKey {
 public:
  // Copyable and movable.
  MlKemPrivateKey(const MlKemPrivateKey& other) = default;
  MlKemPrivateKey& operator=(const MlKemPrivateKey& other) = default;
  MlKemPrivateKey(MlKemPrivateKey&& other) = default;
  MlKemPrivateKey& operator=(MlKemPrivateKey&& other) = default;

  // Creates a new ML-KEM private key from `private_seed_bytes`. Returns an
  // error if `public_key` does not belong to the same key pair as
  // `private_seed_bytes`.
  static util::StatusOr<MlKemPrivateKey> Create(
      const MlKemPublicKey& public_key,
      const RestrictedData& private_seed_bytes, PartialKeyAccessToken token);

  const RestrictedData& GetPrivateSeedBytes(PartialKeyAccessToken token) const
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return private_seed_bytes_;
  }

  const MlKemPublicKey& GetPublicKey() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND override {
    return public_key_;
  }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const {
    return std::make_unique<MlKemPrivateKey>(*this);
  }

 private:
  explicit MlKemPrivateKey(const MlKemPublicKey& public_key,
                           const RestrictedData& private_seed_bytes)
      : public_key_(public_key), private_seed_bytes_(private_seed_bytes) {}

  MlKemPublicKey public_key_;
  RestrictedData private_seed_bytes_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_KEM_ML_KEM_PRIVATE_KEY_H_
