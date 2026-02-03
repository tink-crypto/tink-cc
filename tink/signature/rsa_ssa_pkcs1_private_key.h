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

#ifndef TINK_SIGNATURE_RSA_SSA_PKCS1_PRIVATE_KEY_H_
#define TINK_SIGNATURE_RSA_SSA_PKCS1_PRIVATE_KEY_H_

#include <memory>

#include "absl/base/thread_annotations.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/signature/signature_private_key.h"

namespace crypto {
namespace tink {

class RsaSsaPkcs1PrivateKey final : public SignaturePrivateKey {
 public:
  // Copyable and movable.
  RsaSsaPkcs1PrivateKey(const RsaSsaPkcs1PrivateKey& other)
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

  RsaSsaPkcs1PrivateKey& operator=(const RsaSsaPkcs1PrivateKey& other);
  RsaSsaPkcs1PrivateKey(RsaSsaPkcs1PrivateKey&& other) = default;
  RsaSsaPkcs1PrivateKey& operator=(RsaSsaPkcs1PrivateKey&& other) = default;

  // Creates RsaSsaPkcs1 private key instances.
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty private key builder.
    Builder() = default;

    Builder& SetPublicKey(const RsaSsaPkcs1PublicKey& public_key);

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

    // Creates RsaSsaPkcs1 private key object from this builder.
    absl::StatusOr<RsaSsaPkcs1PrivateKey> Build(PartialKeyAccessToken token);

   private:
    absl::optional<RsaSsaPkcs1PublicKey> public_key_;
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

  const RestrictedData& GetPrimePData(PartialKeyAccessToken token) const {
    return p_;
  }
  const RestrictedData& GetPrimeQData(PartialKeyAccessToken token) const {
    return q_;
  }
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

  const RsaSsaPkcs1PublicKey& GetPublicKey() const override {
    return public_key_;
  }

  const RsaSsaPkcs1Parameters& GetParameters() const override {
    return GetPublicKey().GetParameters();
  }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<RsaSsaPkcs1PrivateKey>(*this);
  }

 private:
  explicit RsaSsaPkcs1PrivateKey(const RsaSsaPkcs1PublicKey& public_key,
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

  RsaSsaPkcs1PublicKey public_key_;
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

#endif  // TINK_SIGNATURE_RSA_SSA_PKCS1_PRIVATE_KEY_H_
