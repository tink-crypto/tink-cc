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

#ifndef TINK_JWT_JWT_ECDSA_PUBLIC_KEY_H_
#define TINK_JWT_JWT_ECDSA_PUBLIC_KEY_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/ec_point.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_signature_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Represents a JWT ECDSA public key to verify a JWT using ECDSA.
class JwtEcdsaPublicKey : public JwtSignaturePublicKey {
 public:
  // Creates JWT ECDSA public key instances.
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty public key builder.
    Builder() = default;

    Builder& SetParameters(const JwtEcdsaParameters& parameters);
    Builder& SetPublicPoint(const EcPoint& public_point);
    Builder& SetIdRequirement(int id_requirement);
    Builder& SetCustomKid(absl::string_view custom_kid);

    // Creates JWT ECDSA public key object from this builder.
    util::StatusOr<JwtEcdsaPublicKey> Build(PartialKeyAccessToken token);

   private:
    util::StatusOr<absl::optional<std::string>> ComputeKid();

    absl::optional<JwtEcdsaParameters> parameters_;
    absl::optional<EcPoint> public_point_;
    absl::optional<int> id_requirement_;
    absl::optional<std::string> custom_kid_;
  };

  // Copyable and movable.
  JwtEcdsaPublicKey(const JwtEcdsaPublicKey& other) = default;
  JwtEcdsaPublicKey& operator=(const JwtEcdsaPublicKey& other) = default;
  JwtEcdsaPublicKey(JwtEcdsaPublicKey&& other) = default;
  JwtEcdsaPublicKey& operator=(JwtEcdsaPublicKey&& other) = default;

  const EcPoint& GetPublicPoint(PartialKeyAccessToken token) const {
    return public_point_;
  }

  const JwtEcdsaParameters& GetParameters() const override {
    return parameters_;
  }

  absl::optional<int32_t> GetIdRequirement() const override {
    return id_requirement_;
  }

  absl::optional<std::string> GetKid() const override { return kid_; }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<JwtEcdsaPublicKey>(*this);
  }

 private:
  JwtEcdsaPublicKey(const JwtEcdsaParameters& parameters,
                    const EcPoint& public_point,
                    absl::optional<int> id_requirement,
                    absl::optional<std::string> kid)
      : parameters_(parameters),
        public_point_(public_point),
        id_requirement_(id_requirement),
        kid_(std::move(kid)) {}

  JwtEcdsaParameters parameters_;
  EcPoint public_point_;
  absl::optional<int> id_requirement_;
  absl::optional<std::string> kid_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_ECDSA_PUBLIC_KEY_H_
