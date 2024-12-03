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

#ifndef TINK_JWT_JWT_RSA_SSA_PSS_PARAMETERS_H_
#define TINK_JWT_JWT_RSA_SSA_PSS_PARAMETERS_H_

#include <memory>
#include <string>

#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/jwt/jwt_signature_parameters.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

class JwtRsaSsaPssParameters : public JwtSignatureParameters {
 public:
  // Strategy for handling the "kid" header.
  enum class KidStrategy : int {
    // The `kid` is the URL safe (RFC 4648 Section 5) base64-encoded big-endian
    // `key_id` in the keyset.
    //
    // In `SignAndEncode()`, Tink always adds the `kid`.
    //
    // In `VerifyAndDecode()`, Tink checks that the `kid` is present and
    // equal to this value.
    //
    // NOTE: This strategy is recommended by Tink.
    kBase64EncodedKeyId = 1,
    // The `kid` header is ignored.
    //
    // In `SignAndEncode()`, Tink does not write a `kid` header.
    //
    // In `VerifyAndDecode()`, Tink ignores the `kid` header.
    kIgnored = 2,
    // The `kid` is fixed. It can be obtained by calling `key.GetKid()`.
    //
    // In `SignAndEncode()`, Tink writes the `kid` header to the
    // value given by `key.GetKid()`.
    //
    // In `VerifyAndDecode()`, if the `kid` is present, it must match
    // `key.GetKid()`. If the `kid` is absent, it will be accepted.
    //
    // NOTE: Tink does not allow random generation of JWT RSASSA-PSS key
    // objects from parameters objects with `KidStrategy::kCustom`.
    kCustom = 3,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Signature algorithm.
  enum class Algorithm : int {
    kPs256 = 1,
    kPs384 = 2,
    kPs512 = 3,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Creates JWT RSASSA-PSS parameters instances.
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty parameters builder.
    Builder() = default;

    Builder& SetAlgorithm(Algorithm algorithm);
    Builder& SetKidStrategy(KidStrategy strategy);
    Builder& SetModulusSizeInBits(int modulus_size_in_bits);
    Builder& SetPublicExponent(const BigInteger& public_exponent);

    // Creates JWT RSASSA-PSS parameters object from this builder. Fails if
    // required fields are not set. The public exponent defaults to F4,
    // if not specified.
    util::StatusOr<JwtRsaSsaPssParameters> Build();

   private:
    static BigInteger CreateDefaultPublicExponent();

    absl::optional<Algorithm> algorithm_ = absl::nullopt;
    absl::optional<KidStrategy> kid_strategy_ = absl::nullopt;
    absl::optional<int> modulus_size_in_bits_ = absl::nullopt;
    // Defaults to F4.
    BigInteger public_exponent_ = CreateDefaultPublicExponent();
  };

  // Copyable and movable.
  JwtRsaSsaPssParameters(const JwtRsaSsaPssParameters& other) = default;
  JwtRsaSsaPssParameters& operator=(const JwtRsaSsaPssParameters& other) =
      default;
  JwtRsaSsaPssParameters(JwtRsaSsaPssParameters&& other) = default;
  JwtRsaSsaPssParameters& operator=(JwtRsaSsaPssParameters&& other) = default;

  Algorithm GetAlgorithm() const { return algorithm_; }

  KidStrategy GetKidStrategy() const { return kid_strategy_; }

  int GetModulusSizeInBits() const { return modulus_size_in_bits_; }

  const BigInteger& GetPublicExponent() const { return public_exponent_; }

  bool AllowKidAbsent() const override {
    return kid_strategy_ == KidStrategy::kCustom ||
           kid_strategy_ == KidStrategy::kIgnored;
  }

  bool HasIdRequirement() const override {
    return kid_strategy_ == KidStrategy::kBase64EncodedKeyId;
  }

  bool operator==(const Parameters& other) const override;

  std::unique_ptr<Parameters> Clone() const {
    return std::make_unique<JwtRsaSsaPssParameters>(*this);
  }

 private:
  explicit JwtRsaSsaPssParameters(Algorithm algorithm, KidStrategy kid_strategy,
                                  int modulus_size_in_bits,
                                  const BigInteger& public_exponent)
      : algorithm_(algorithm),
        kid_strategy_(kid_strategy),
        modulus_size_in_bits_(modulus_size_in_bits),
        public_exponent_(public_exponent) {}

  Algorithm algorithm_;
  KidStrategy kid_strategy_;
  int modulus_size_in_bits_;
  BigInteger public_exponent_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_RSA_SSA_PSS_PARAMETERS_H_
