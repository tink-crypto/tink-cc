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

#ifndef TINK_SIGNATURE_SLH_DSA_PRIVATE_KEY_H_
#define TINK_SIGNATURE_SLH_DSA_PRIVATE_KEY_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/signature/signature_private_key.h"
#include "tink/signature/slh_dsa_public_key.h"

namespace crypto {
namespace tink {

class SlhDsaPrivateKey final : public SignaturePrivateKey {
 public:
  // Copyable and movable.
  SlhDsaPrivateKey(const SlhDsaPrivateKey& other) = default;
  SlhDsaPrivateKey& operator=(const SlhDsaPrivateKey& other) = default;
  SlhDsaPrivateKey(SlhDsaPrivateKey&& other) = default;
  SlhDsaPrivateKey& operator=(SlhDsaPrivateKey&& other) = default;

  // Creates a new SLH-DSA private key from `private_key_bytes`. Returns an
  // error if `public_key` does not belong to the same key pair as
  // `private_key_bytes`.
  //
  // This function unconditionally returns an error in non-BoringSSL builds.
  static absl::StatusOr<SlhDsaPrivateKey> Create(
      const SlhDsaPublicKey& public_key,
      const RestrictedData& private_key_bytes, PartialKeyAccessToken token);

  const RestrictedData& GetPrivateKeyBytes(PartialKeyAccessToken token) const {
    return private_key_bytes_;
  }

  const SlhDsaPublicKey& GetPublicKey() const override { return public_key_; }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<SlhDsaPrivateKey>(*this);
  }

 private:
  explicit SlhDsaPrivateKey(const SlhDsaPublicKey& public_key,
                            const RestrictedData& private_key_bytes)
      : public_key_(public_key), private_key_bytes_(private_key_bytes) {}

  SlhDsaPublicKey public_key_;
  RestrictedData private_key_bytes_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_SLH_DSA_PRIVATE_KEY_H_
