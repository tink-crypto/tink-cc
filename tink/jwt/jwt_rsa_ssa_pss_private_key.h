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

#ifndef TINK_JWT_JWT_RSA_SSA_PSS_PRIVATE_KEY_H_
#define TINK_JWT_JWT_RSA_SSA_PSS_PRIVATE_KEY_H_

#include <memory>
#include <optional>

#include "absl/base/thread_annotations.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"
#include "tink/jwt/jwt_signature_private_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {

// Represents a JWT RSASSA-PSS private key to sign a JWT using RSA.
class JwtRsaSsaPssPrivateKey final : public JwtSignaturePrivateKey {
 public:
  // Copyable and movable.
  JwtRsaSsaPssPrivateKey(const JwtRsaSsaPssPrivateKey& other) = default;
  JwtRsaSsaPssPrivateKey& operator=(const JwtRsaSsaPssPrivateKey& other) =
      default;
  JwtRsaSsaPssPrivateKey(JwtRsaSsaPssPrivateKey&& other) = default;
  JwtRsaSsaPssPrivateKey& operator=(JwtRsaSsaPssPrivateKey&& other) = default;

  // Creates JWT RSASSA-PSS private key instances.
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty private key builder.
    Builder() = default;

    Builder& SetPublicKey(const JwtRsaSsaPssPublicKey& public_key);
    Builder& SetPrimeP(const RestrictedData& p);
    Builder& SetPrimeQ(const RestrictedData& q);
    Builder& SetPrimeExponentP(const RestrictedData& dp);
    Builder& SetPrimeExponentQ(const RestrictedData& dq);
    Builder& SetPrivateExponent(const RestrictedData& d);
    Builder& SetCrtCoefficient(const RestrictedData& q_inv);

    // Creates JwtRsaSsaPss private key object from this builder.
    absl::StatusOr<JwtRsaSsaPssPrivateKey> Build(PartialKeyAccessToken token);

    // Create JWT RsaSsaPss private key object, and perform the following
    // operations on the input:
    // * Trim leading zeros of `p` and `q`
    // * Pad/trim `dp`, `q_inv`, `d` and `dq` so that `dp.size()==p.size()`,
    // `q_inv.size()==p.size()`, `d.size() == n.size()` and  `dq.size() ==
    // q.size()`
    absl::StatusOr<JwtRsaSsaPssPrivateKey> BuildAllowNonConstantTime(
        PartialKeyAccessToken token);

   private:
    std::optional<JwtRsaSsaPssPublicKey> public_key_;
    std::optional<RestrictedData> p_;
    std::optional<RestrictedData> q_;
    std::optional<RestrictedData> dp_;
    std::optional<RestrictedData> dq_;
    std::optional<RestrictedData> d_;
    std::optional<RestrictedData> q_inv_;
  };

  const RestrictedData& GetPrimePData(PartialKeyAccessToken token) const {
    return p_;
  }

  const RestrictedData& GetPrimeQData(PartialKeyAccessToken token) const {
    return q_;
  }

  const RestrictedData& GetPrivateExponentData(
      PartialKeyAccessToken token) const {
    return d_;
  }

  const RestrictedData& GetPrimeExponentPData(
      PartialKeyAccessToken token) const {
    return dp_;
  }

  const RestrictedData& GetPrimeExponentQData(
      PartialKeyAccessToken token) const {
    return dq_;
  }

  const RestrictedData& GetCrtCoefficientData(
      PartialKeyAccessToken token) const {
    return q_inv_;
  }

  const JwtRsaSsaPssPublicKey& GetPublicKey() const override {
    return public_key_;
  }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<JwtRsaSsaPssPrivateKey>(*this);
  }

 private:
  explicit JwtRsaSsaPssPrivateKey(const JwtRsaSsaPssPublicKey& public_key,
                                  const RestrictedData& p,
                                  const RestrictedData& q,
                                  const RestrictedData& dp,
                                  const RestrictedData& dq,
                                  const RestrictedData& d,
                                  const RestrictedData& q_inv)
      : public_key_(public_key),
        p_(p),
        q_(q),
        dp_(dp),
        dq_(dq),
        d_(d),
        q_inv_(q_inv) {}

  JwtRsaSsaPssPublicKey public_key_;
  RestrictedData p_;
  RestrictedData q_;
  RestrictedData dp_;
  RestrictedData dq_;
  RestrictedData d_;
  RestrictedData q_inv_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_RSA_SSA_PSS_PRIVATE_KEY_H_
