// Copyright 2026 Google LLC
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

#ifndef TINK_JWT_JWT_ML_DSA_PUBLIC_KEY_H_
#define TINK_JWT_JWT_ML_DSA_PUBLIC_KEY_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/jwt/jwt_signature_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"

namespace crypto {
namespace tink {

// Represents a JWT ML-DSA public key to verify a JWT using ML-DSA.
class JwtMlDsaPublicKey final : public JwtSignaturePublicKey {
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

    Builder& SetParameters(const JwtMlDsaParameters& parameters);
    Builder& SetPublicKeyBytes(absl::string_view public_key_bytes);
    Builder& SetIdRequirement(int id_requirement);
    Builder& SetCustomKid(absl::string_view custom_kid);

    // Creates JWT ML-DSA public key object from this builder.
    absl::StatusOr<JwtMlDsaPublicKey> Build(PartialKeyAccessToken token);

   private:
    absl::StatusOr<std::optional<std::string>> ComputeKid();

    std::optional<JwtMlDsaParameters> parameters_;
    std::optional<std::string> public_key_bytes_;
    std::optional<int> id_requirement_;
    std::optional<std::string> custom_kid_;
  };

  // Copyable and movable.
  JwtMlDsaPublicKey(const JwtMlDsaPublicKey& other) = default;
  JwtMlDsaPublicKey& operator=(const JwtMlDsaPublicKey& other) = default;
  JwtMlDsaPublicKey(JwtMlDsaPublicKey&& other) = default;
  JwtMlDsaPublicKey& operator=(JwtMlDsaPublicKey&& other) = default;

  absl::string_view GetPublicKeyBytes(PartialKeyAccessToken token) const
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return public_key_bytes_;
  }

  const JwtMlDsaParameters& GetParameters() const override {
    return parameters_;
  }

  std::optional<int32_t> GetIdRequirement() const override {
    return id_requirement_;
  }

  std::optional<std::string> GetKid() const override { return kid_; }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<JwtMlDsaPublicKey>(*this);
  }

 private:
  JwtMlDsaPublicKey(const JwtMlDsaParameters& parameters,
                    absl::string_view public_key_bytes,
                    std::optional<int> id_requirement,
                    std::optional<std::string> kid)
      : parameters_(parameters),
        public_key_bytes_(public_key_bytes),
        id_requirement_(id_requirement),
        kid_(std::move(kid)) {}

  JwtMlDsaParameters parameters_;
  std::string public_key_bytes_;
  std::optional<int> id_requirement_;
  std::optional<std::string> kid_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_ML_DSA_PUBLIC_KEY_H_
