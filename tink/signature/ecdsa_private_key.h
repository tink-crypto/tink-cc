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

#ifndef TINK_SIGNATURE_ECDSA_PRIVATE_KEY_H_
#define TINK_SIGNATURE_ECDSA_PRIVATE_KEY_H_

#include <memory>

#include "absl/base/call_once.h"
#include "absl/base/macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/signature_private_key.h"

namespace crypto {
namespace tink {

// Representation of the sign function for an ECDSA digital signature
// primitive.
class EcdsaPrivateKey final : public SignaturePrivateKey {
 public:
  // Copyable and movable.
  EcdsaPrivateKey(const EcdsaPrivateKey& other)
      : public_key_(other.public_key_),
        private_key_value_(other.private_key_value_) {
    absl::call_once(other.once_, [&] {
      if (other.private_key_value_big_integer_ != nullptr) {
        private_key_value_big_integer_ = std::make_unique<RestrictedBigInteger>(
            *other.private_key_value_big_integer_);
      }
    });
  }
  EcdsaPrivateKey& operator=(const EcdsaPrivateKey& other) = delete;
  EcdsaPrivateKey(EcdsaPrivateKey&& other) = default;
  EcdsaPrivateKey& operator=(EcdsaPrivateKey&& other) = default;

  // Returns an error if the input of private_key_value is not of length
  // public_key.GetParameters().GetPrivateKeyLength().
  static absl::StatusOr<EcdsaPrivateKey> Create(
      const EcdsaPublicKey& public_key, const RestrictedData& private_key_value,
      PartialKeyAccessToken token);

  const RestrictedData& GetPrivateKey(PartialKeyAccessToken token) const {
    return private_key_value_;
  }

  // Pads private_key_value to GetPrivateKeyLength() if needed,
  // truncates leading zeros if needed.
  static absl::StatusOr<EcdsaPrivateKey> CreateAllowNonConstantTime(
      const EcdsaPublicKey& public_key, const RestrictedData& private_key_value,
      PartialKeyAccessToken token);
  const RestrictedData& GetPrivateKey() const;

  // Deprecated. Will be removed in Tink 3.0.0.
  ABSL_DEPRECATE_AND_INLINE()
  static absl::StatusOr<EcdsaPrivateKey> Create(
      const EcdsaPublicKey& public_key,
      const RestrictedBigInteger& private_key_value,
      PartialKeyAccessToken token) {
    absl::string_view private_key_value_string =
        private_key_value.GetSecret(InsecureSecretKeyAccess::Get());

    return EcdsaPrivateKey::CreateAllowNonConstantTime(
        public_key,
        RestrictedData(private_key_value_string,
                       InsecureSecretKeyAccess::Get()),
        token);
  }

  const RestrictedBigInteger& GetPrivateKeyValue(
      PartialKeyAccessToken token) const;

  const EcdsaPublicKey& GetPublicKey() const override { return public_key_; }

  const EcdsaParameters& GetParameters() const override {
    return public_key_.GetParameters();
  }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<EcdsaPrivateKey>(*this);
  };

 private:
  explicit EcdsaPrivateKey(const EcdsaPublicKey& public_key,
                           const RestrictedData& private_key_value)
      : public_key_(public_key), private_key_value_(private_key_value) {}

  EcdsaPublicKey public_key_;
  RestrictedData private_key_value_;

  mutable absl::once_flag once_;
  mutable std::unique_ptr<RestrictedBigInteger> private_key_value_big_integer_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_ECDSA_PRIVATE_KEY_H_
