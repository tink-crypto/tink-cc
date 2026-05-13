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

#ifndef TINK_JWT_JWT_ML_DSA_PARAMETERS_H_
#define TINK_JWT_JWT_ML_DSA_PARAMETERS_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/jwt/jwt_signature_parameters.h"
#include "tink/parameters.h"

namespace crypto {
namespace tink {

// Describes the parameters of a JWT ML-DSA signature key pair.
class JwtMlDsaParameters : public JwtSignatureParameters {
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
    // NOTE: Tink does not allow random generation of JWT ML-DSA key objects
    // from parameters objects with `KidStrategy::kCustom`.
    kCustom = 3,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Description of the ML-DSA instance.
  enum class Algorithm : int {
    kMlDsa44 = 1,
    kMlDsa65 = 2,
    kMlDsa87 = 3,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Copyable and movable.
  JwtMlDsaParameters(const JwtMlDsaParameters& other) = default;
  JwtMlDsaParameters& operator=(const JwtMlDsaParameters& other) = default;
  JwtMlDsaParameters(JwtMlDsaParameters&& other) = default;
  JwtMlDsaParameters& operator=(JwtMlDsaParameters&& other) = default;

  // Creates JWT ML-DSA parameters object. Returns an error status if
  // if either `kid_strategy` is invalid or `algorithm` is invalid.
  static absl::StatusOr<JwtMlDsaParameters> Create(KidStrategy kid_strategy,
                                                   Algorithm algorithm);

  KidStrategy GetKidStrategy() const { return kid_strategy_; }

  // Returns the ML-DSA key instance (44, 65 or 87).
  Algorithm GetAlgorithm() const { return algorithm_; }

  bool AllowKidAbsent() const override {
    return kid_strategy_ == KidStrategy::kCustom ||
           kid_strategy_ == KidStrategy::kIgnored;
  }

  bool HasIdRequirement() const override {
    return kid_strategy_ == KidStrategy::kBase64EncodedKeyId;
  }

  bool operator==(const Parameters& other) const override;

  std::unique_ptr<Parameters> Clone() const override {
    return std::make_unique<JwtMlDsaParameters>(*this);
  }

 private:
  JwtMlDsaParameters(KidStrategy kid_strategy, Algorithm algorithm)
      : kid_strategy_(kid_strategy), algorithm_(algorithm) {}

  KidStrategy kid_strategy_;
  Algorithm algorithm_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_ML_DSA_PARAMETERS_H_
