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

#ifndef TINK_JWT_JWT_RSA_SSA_PKCS1_PUBLIC_KEY_H_
#define TINK_JWT_JWT_RSA_SSA_PKCS1_PUBLIC_KEY_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_signature_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"

namespace crypto {
namespace tink {

// Represents a JWT RSASSA-PKCS1 public key to verify a JWT using RSA.
class JwtRsaSsaPkcs1PublicKey final : public JwtSignaturePublicKey {
 public:
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty public key builder.
    Builder() = default;

    Builder& SetParameters(const JwtRsaSsaPkcs1Parameters& parameters);
    Builder& SetModulus(const BigInteger& modulus);
    Builder& SetIdRequirement(int id_requirement);
    Builder& SetCustomKid(absl::string_view custom_kid);

    // Creates JWT RSASSA-PKCS1 public key object from this builder.
    absl::StatusOr<JwtRsaSsaPkcs1PublicKey> Build(PartialKeyAccessToken token);

   private:
    absl::StatusOr<absl::optional<std::string>> ComputeKid();

    absl::optional<JwtRsaSsaPkcs1Parameters> parameters_;
    absl::optional<BigInteger> modulus_;
    absl::optional<int> id_requirement_;
    absl::optional<std::string> custom_kid_;
  };

  // Copyable and movable.
  JwtRsaSsaPkcs1PublicKey(const JwtRsaSsaPkcs1PublicKey& other) = default;
  JwtRsaSsaPkcs1PublicKey& operator=(const JwtRsaSsaPkcs1PublicKey& other) =
      default;
  JwtRsaSsaPkcs1PublicKey(JwtRsaSsaPkcs1PublicKey&& other) = default;
  JwtRsaSsaPkcs1PublicKey& operator=(JwtRsaSsaPkcs1PublicKey&& other) = default;

  const BigInteger& GetModulus(PartialKeyAccessToken token) const {
    return modulus_;
  }

  const JwtRsaSsaPkcs1Parameters& GetParameters() const override {
    return parameters_;
  }

  absl::optional<int32_t> GetIdRequirement() const override {
    return id_requirement_;
  }

  absl::optional<std::string> GetKid() const override { return kid_; }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<JwtRsaSsaPkcs1PublicKey>(*this);
  }

 private:
  explicit JwtRsaSsaPkcs1PublicKey(const JwtRsaSsaPkcs1Parameters& parameters,
                                   const BigInteger& modulus,
                                   absl::optional<int> id_requirement,
                                   absl::optional<std::string> kid)
      : parameters_(parameters),
        modulus_(modulus),
        id_requirement_(id_requirement),
        kid_(std::move(kid)) {}

  JwtRsaSsaPkcs1Parameters parameters_;
  BigInteger modulus_;
  absl::optional<int> id_requirement_;
  absl::optional<std::string> kid_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_RSA_SSA_PKCS1_PUBLIC_KEY_H_
