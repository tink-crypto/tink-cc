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

#ifndef TINK_JWT_JWT_RSA_SSA_PSS_PUBLIC_KEY_H_
#define TINK_JWT_JWT_RSA_SSA_PSS_PUBLIC_KEY_H_

#include <cstdint>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/jwt/jwt_signature_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Represents a JWT RSASSA-PSS public key to verify a JWT using RSA.
class JwtRsaSsaPssPublicKey : public JwtSignaturePublicKey {
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

    Builder& SetParameters(const JwtRsaSsaPssParameters& parameters);
    Builder& SetModulus(const BigInteger& modulus);
    Builder& SetIdRequirement(int id_requirement);
    Builder& SetCustomKid(absl::string_view custom_kid);

    // Creates JWT RSASSA-PSS public key object from this builder.
    util::StatusOr<JwtRsaSsaPssPublicKey> Build(PartialKeyAccessToken token);

   private:
    util::StatusOr<absl::optional<std::string>> ComputeKid();

    absl::optional<JwtRsaSsaPssParameters> parameters_;
    absl::optional<BigInteger> modulus_;
    absl::optional<int> id_requirement_;
    absl::optional<std::string> custom_kid_;
  };

  // Copyable and movable.
  JwtRsaSsaPssPublicKey(const JwtRsaSsaPssPublicKey& other) = default;
  JwtRsaSsaPssPublicKey& operator=(const JwtRsaSsaPssPublicKey& other) =
      default;
  JwtRsaSsaPssPublicKey(JwtRsaSsaPssPublicKey&& other) = default;
  JwtRsaSsaPssPublicKey& operator=(JwtRsaSsaPssPublicKey&& other) = default;

  const BigInteger& GetModulus(PartialKeyAccessToken token) const {
    return modulus_;
  }

  const JwtRsaSsaPssParameters& GetParameters() const override {
    return parameters_;
  }

  absl::optional<int32_t> GetIdRequirement() const override {
    return id_requirement_;
  }

  absl::optional<std::string> GetKid() const override { return kid_; }

  bool operator==(const Key& other) const override;

 private:
  explicit JwtRsaSsaPssPublicKey(const JwtRsaSsaPssParameters& parameters,
                                   const BigInteger& modulus,
                                   absl::optional<int> id_requirement,
                                   absl::optional<std::string> kid)
      : parameters_(parameters),
        modulus_(modulus),
        id_requirement_(id_requirement),
        kid_(std::move(kid)) {}

  JwtRsaSsaPssParameters parameters_;
  BigInteger modulus_;
  absl::optional<int> id_requirement_;
  absl::optional<std::string> kid_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_RSA_SSA_PSS_PUBLIC_KEY_H_
