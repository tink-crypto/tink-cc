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

#ifndef TINK_SIGNATURE_ML_DSA_PRIVATE_KEY_H_
#define TINK_SIGNATURE_ML_DSA_PRIVATE_KEY_H_

#include <memory>

#include "absl/base/attributes.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/signature/ml_dsa_public_key.h"
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

  // Creates a new ML-DSA private key from `private_seed_bytes`. Returns an
  // error if `public_key` does not belong to the same key pair as
  // `private_seed_bytes`.
  static util::StatusOr<MlDsaPrivateKey> Create(
      const MlDsaPublicKey& public_key,
      const RestrictedData& private_seed_bytes, PartialKeyAccessToken token);

  // Returns the seed that was used to generate the private key.
  //
  // Note that this is a 32-byte seed, from which the private key is derived via
  // algorithm 6 "ML-DSA.KeyGen_internal" of the FIPS 204 standard
  // (https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf).
  //
  // This is NOT the private key encoding described in algorithm 24 "skEncode"
  // of the FIPS 204 standard. Tink doesn't currently provide a way to
  // import/export an ML-DSA private key in this canonical secret key encoding.
  const RestrictedData& GetPrivateSeedBytes(PartialKeyAccessToken token) const
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return private_seed_bytes_;
  }

  const MlDsaPublicKey& GetPublicKey() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND override {
    return public_key_;
  }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const {
    return std::make_unique<MlDsaPrivateKey>(*this);
  }

 private:
  explicit MlDsaPrivateKey(const MlDsaPublicKey& public_key,
                           const RestrictedData& private_seed_bytes)
      : public_key_(public_key), private_seed_bytes_(private_seed_bytes) {}

  MlDsaPublicKey public_key_;
  RestrictedData private_seed_bytes_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_ML_DSA_PRIVATE_KEY_H_
