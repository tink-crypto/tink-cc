// Copyright 2023 Google LLC
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

#ifndef TINK_SIGNATURE_RSA_SSA_PSS_PRIVATE_KEY_H_
#define TINK_SIGNATURE_RSA_SSA_PSS_PRIVATE_KEY_H_

#include <memory>

#include "absl/base/thread_annotations.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/signature/signature_private_key.h"

namespace crypto {
namespace tink {

class RsaSsaPssPrivateKey final : public SignaturePrivateKey {
 public:
  // Copyable and movable.
  RsaSsaPssPrivateKey(const RsaSsaPssPrivateKey& other) = default;
  RsaSsaPssPrivateKey& operator=(const RsaSsaPssPrivateKey& other) = default;
  RsaSsaPssPrivateKey(RsaSsaPssPrivateKey&& other) = default;
  RsaSsaPssPrivateKey& operator=(RsaSsaPssPrivateKey&& other) = default;

  // Creates RsaSsaPss private key instances.
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = delete;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty private key builder.
    Builder() = default;

    Builder& SetPublicKey(const RsaSsaPssPublicKey& public_key);

    Builder& SetPrimeP(const RestrictedData& p);
    Builder& SetPrimeQ(const RestrictedData& q);
    Builder& SetPrimeExponentP(const RestrictedData& dp);
    Builder& SetPrimeExponentQ(const RestrictedData& dq);
    Builder& SetPrivateExponent(const RestrictedData& d);
    Builder& SetCrtCoefficient(const RestrictedData& q_inv);

    // Creates RsaSsaPss private key object from this builder.
    absl::StatusOr<RsaSsaPssPrivateKey> Build(PartialKeyAccessToken token);

    // Create RsaSsaPss private key object, and perform the following
    // operations on the input:
    // * Trim leading zeros of `p` and `q`
    // * Pad/trim `dp`, `q_inv`, `d` and `dq` so that `dp.size()==p.size()`,
    // `q_inv.size()==p.size()`, `d.size() == n.size()` and  `dq.size() ==
    // q.size()`
    absl::StatusOr<RsaSsaPssPrivateKey> BuildAllowNonConstantTime(
        PartialKeyAccessToken token);

   private:
    absl::optional<RsaSsaPssPublicKey> public_key_;
    absl::optional<RestrictedData> p_;
    absl::optional<RestrictedData> q_;
    absl::optional<RestrictedData> dp_;
    absl::optional<RestrictedData> dq_;
    absl::optional<RestrictedData> d_;
    absl::optional<RestrictedData> q_inv_;
  };

  const RestrictedData& GetPrimePData() const { return p_; }

  const RestrictedData& GetPrimeQData() const { return q_; }

  const RestrictedData& GetPrimeExponentPData() const { return dp_; }

  const RestrictedData& GetPrimeExponentQData() const { return dq_; }

  const RestrictedData& GetPrivateExponentData() const { return d_; }

  const RestrictedData& GetCrtCoefficientData() const { return q_inv_; }

  const RsaSsaPssPublicKey& GetPublicKey() const override {
    return public_key_;
  }

  const RsaSsaPssParameters& GetParameters() const override {
    return GetPublicKey().GetParameters();
  }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<RsaSsaPssPrivateKey>(*this);
  };

 private:
  explicit RsaSsaPssPrivateKey(const RsaSsaPssPublicKey& public_key,
                               RestrictedData p, RestrictedData q,
                               RestrictedData dp, RestrictedData dq,
                               RestrictedData d, RestrictedData q_inv)
      : public_key_(public_key),
        p_(p),
        q_(q),
        dp_(dp),
        dq_(dq),
        d_(d),
        q_inv_(q_inv) {}

  RsaSsaPssPublicKey public_key_;
  RestrictedData p_;
  RestrictedData q_;
  RestrictedData dp_;
  RestrictedData dq_;
  RestrictedData d_;
  RestrictedData q_inv_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_RSA_SSA_PSS_PRIVATE_KEY_H_
