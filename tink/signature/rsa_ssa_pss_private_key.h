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
  RsaSsaPssPrivateKey(const RsaSsaPssPrivateKey& other)
      : public_key_(other.public_key_),
        p_(other.p_),
        q_(other.q_),
        dp_(other.dp_),
        dq_(other.dq_),
        d_(other.d_),
        q_inv_(other.q_inv_) {
    absl::MutexLock lock(other.mutex_);
    p_big_integer_ = other.p_big_integer_;
    q_big_integer_ = other.q_big_integer_;
    dp_big_integer_ = other.dp_big_integer_;
    dq_big_integer_ = other.dq_big_integer_;
    d_big_integer_ = other.d_big_integer_;
    q_inv_big_integer_ = other.q_inv_big_integer_;
  }

  RsaSsaPssPrivateKey& operator=(const RsaSsaPssPrivateKey& other);
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

    // Deprecated: will be removed in Tink 3.0.0

    Builder& SetPrimeP(const RestrictedBigInteger& p);
    Builder& SetPrimeQ(const RestrictedBigInteger& q);
    Builder& SetPrimeExponentP(const RestrictedBigInteger& dp);
    Builder& SetPrimeExponentQ(const RestrictedBigInteger& dq);
    Builder& SetPrivateExponent(const RestrictedBigInteger& d);
    Builder& SetCrtCoefficient(const RestrictedBigInteger& q_inv);

    // Creates RsaSsaPss private key object from this builder.
    absl::StatusOr<RsaSsaPssPrivateKey> Build(PartialKeyAccessToken token);

   private:
    absl::optional<RsaSsaPssPublicKey> public_key_;
    absl::optional<RestrictedData> p_;
    absl::optional<RestrictedData> q_;
    absl::optional<RestrictedData> dp_;
    absl::optional<RestrictedData> dq_;
    absl::optional<RestrictedData> d_;
    absl::optional<RestrictedData> q_inv_;
    absl::optional<RestrictedBigInteger> p_big_integer_;
    absl::optional<RestrictedBigInteger> q_big_integer_;
    absl::optional<RestrictedBigInteger> dp_big_integer_;
    absl::optional<RestrictedBigInteger> dq_big_integer_;
    absl::optional<RestrictedBigInteger> d_big_integer_;
    absl::optional<RestrictedBigInteger> q_inv_big_integer_;
  };

  const RestrictedData& GetPrimePData() const { return p_; }

  const RestrictedData& GetPrimeQData() const { return q_; }

  const RestrictedData& GetPrimeExponentPData() const { return dp_; }

  const RestrictedData& GetPrimeExponentQData() const { return dq_; }

  const RestrictedData& GetPrivateExponentData() const { return d_; }

  const RestrictedData& GetCrtCoefficientData() const { return q_inv_; }

  // Deprecated: will be removed in Tink 3.0.0

  const RestrictedBigInteger& GetPrimeP(PartialKeyAccessToken token) const;

  const RestrictedBigInteger& GetPrimeQ(PartialKeyAccessToken token) const;

  const RestrictedBigInteger& GetPrivateExponent() const;

  const RestrictedBigInteger& GetPrimeExponentP() const;

  const RestrictedBigInteger& GetPrimeExponentQ() const;

  const RestrictedBigInteger& GetCrtCoefficient() const;

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

  mutable absl::Mutex mutex_;
  mutable absl::optional<RestrictedBigInteger> p_big_integer_
      ABSL_GUARDED_BY(mutex_);
  mutable absl::optional<RestrictedBigInteger> q_big_integer_
      ABSL_GUARDED_BY(mutex_);
  mutable absl::optional<RestrictedBigInteger> dp_big_integer_
      ABSL_GUARDED_BY(mutex_);
  mutable absl::optional<RestrictedBigInteger> dq_big_integer_
      ABSL_GUARDED_BY(mutex_);
  mutable absl::optional<RestrictedBigInteger> d_big_integer_
      ABSL_GUARDED_BY(mutex_);
  mutable absl::optional<RestrictedBigInteger> q_inv_big_integer_
      ABSL_GUARDED_BY(mutex_);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_RSA_SSA_PSS_PRIVATE_KEY_H_
