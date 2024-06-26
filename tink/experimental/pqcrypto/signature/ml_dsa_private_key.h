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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_ML_DSA_PRIVATE_KEY_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_ML_DSA_PRIVATE_KEY_H_

#include "absl/base/attributes.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/signature/signature_private_key.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Representation of the signing function for the ML-DSA digital signature
// primitive.
class MlDsaPrivateKey : public SignaturePrivateKey {
 public:
  // Copyable and movable.
  MlDsaPrivateKey(const MlDsaPrivateKey& other) = default;
  MlDsaPrivateKey& operator=(const MlDsaPrivateKey& other) = default;
  MlDsaPrivateKey(MlDsaPrivateKey&& other) = default;
  MlDsaPrivateKey& operator=(MlDsaPrivateKey&& other) = default;

  // Creates a new ML-DSA private key from `private_key_bytes`. Returns an
  // error if `public_key` does not belong to the same key pair as
  // `private_key_bytes`.
  static util::StatusOr<MlDsaPrivateKey> Create(
      const MlDsaPublicKey& public_key, const RestrictedData& private_key_bytes,
      PartialKeyAccessToken token);

  const RestrictedData& GetPrivateKeyBytes(PartialKeyAccessToken token) const
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return private_key_bytes_;
  }

  const MlDsaPublicKey& GetPublicKey() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND override {
    return public_key_;
  }

  bool operator==(const Key& other) const override;

 private:
  explicit MlDsaPrivateKey(const MlDsaPublicKey& public_key,
                           const RestrictedData& private_key_bytes)
      : public_key_(public_key), private_key_bytes_(private_key_bytes) {}

  MlDsaPublicKey public_key_;
  RestrictedData private_key_bytes_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_ML_DSA_PRIVATE_KEY_H_
