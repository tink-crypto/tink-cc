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

#include "tink/signature/rsa_ssa_pss_private_key.h"

#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#include "tink/internal/rsa_util.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_big_integer.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"

namespace crypto {
namespace tink {
namespace {

absl::Status ValidateKeyPair(const RsaSsaPssPublicKey& public_key,
                             const RestrictedData& p, const RestrictedData& q,
                             const RestrictedData& d, const RestrictedData& dp,
                             const RestrictedData& dq,
                             const RestrictedData& q_inv,
                             PartialKeyAccessToken token) {
  absl::StatusOr<internal::SslUniquePtr<RSA>> rsa =
      internal::RsaPrivateKeyToRsaFixedSizeInputs(internal::RsaPrivateKey{
          /*n=*/std::string(public_key.GetModulus(token).GetValue()),
          /*e=*/
          std::string(
              public_key.GetParameters().GetPublicExponent().GetValue()),
          /*d=*/d.Get(InsecureSecretKeyAccess::Get()),
          /*p=*/p.Get(InsecureSecretKeyAccess::Get()),
          /*q=*/q.Get(InsecureSecretKeyAccess::Get()),
          /*dp=*/dp.Get(InsecureSecretKeyAccess::Get()),
          /*dq=*/dq.Get(InsecureSecretKeyAccess::Get()),
          /*crt=*/q_inv.Get(InsecureSecretKeyAccess::Get()),
      });
  return rsa.status();
}

}  // namespace

RsaSsaPssPrivateKey& RsaSsaPssPrivateKey::operator=(
    const RsaSsaPssPrivateKey& other) {
  if (this == &other) {
    return *this;
  }

  absl::optional<RestrictedBigInteger> p_big_integer;
  absl::optional<RestrictedBigInteger> q_big_integer;
  absl::optional<RestrictedBigInteger> dp_big_integer;
  absl::optional<RestrictedBigInteger> dq_big_integer;
  absl::optional<RestrictedBigInteger> d_big_integer;
  absl::optional<RestrictedBigInteger> q_inv_big_integer;
  {
    absl::MutexLock lock(other.mutex_);
    p_big_integer = other.p_big_integer_;
    q_big_integer = other.q_big_integer_;
    dp_big_integer = other.dp_big_integer_;
    dq_big_integer = other.dq_big_integer_;
    d_big_integer = other.d_big_integer_;
    q_inv_big_integer = other.q_inv_big_integer_;
  }

  public_key_ = other.public_key_;
  p_ = other.p_;
  q_ = other.q_;
  dp_ = other.dp_;
  dq_ = other.dq_;
  d_ = other.d_;
  q_inv_ = other.q_inv_;

  absl::MutexLock lock(mutex_);
  p_big_integer_ = p_big_integer;
  q_big_integer_ = q_big_integer;
  dp_big_integer_ = dp_big_integer;
  dq_big_integer_ = dq_big_integer;
  d_big_integer_ = d_big_integer;
  q_inv_big_integer_ = q_inv_big_integer;
  return *this;
}

const RestrictedBigInteger& RsaSsaPssPrivateKey::GetPrimeP(
    PartialKeyAccessToken token) const {
  absl::MutexLock lock(mutex_);
  if (!p_big_integer_.has_value()) {
    p_big_integer_.emplace(p_.GetSecret(InsecureSecretKeyAccess::Get()),
                           InsecureSecretKeyAccess::Get());
  }
  return *p_big_integer_;
}

const RestrictedBigInteger& RsaSsaPssPrivateKey::GetPrimeQ(
    PartialKeyAccessToken token) const {
  absl::MutexLock lock(mutex_);
  if (!q_big_integer_.has_value()) {
    q_big_integer_.emplace(q_.GetSecret(InsecureSecretKeyAccess::Get()),
                           InsecureSecretKeyAccess::Get());
  }
  return *q_big_integer_;
}

const RestrictedBigInteger& RsaSsaPssPrivateKey::GetPrivateExponent() const {
  absl::MutexLock lock(mutex_);
  if (!d_big_integer_.has_value()) {
    d_big_integer_.emplace(d_.GetSecret(InsecureSecretKeyAccess::Get()),
                           InsecureSecretKeyAccess::Get());
  }
  return *d_big_integer_;
}

const RestrictedBigInteger& RsaSsaPssPrivateKey::GetPrimeExponentP() const {
  absl::MutexLock lock(mutex_);
  if (!dp_big_integer_.has_value()) {
    dp_big_integer_.emplace(dp_.GetSecret(InsecureSecretKeyAccess::Get()),
                            InsecureSecretKeyAccess::Get());
  }
  return *dp_big_integer_;
}

const RestrictedBigInteger& RsaSsaPssPrivateKey::GetPrimeExponentQ() const {
  absl::MutexLock lock(mutex_);
  if (!dq_big_integer_.has_value()) {
    dq_big_integer_.emplace(dq_.GetSecret(InsecureSecretKeyAccess::Get()),
                            InsecureSecretKeyAccess::Get());
  }
  return *dq_big_integer_;
}

const RestrictedBigInteger& RsaSsaPssPrivateKey::GetCrtCoefficient() const {
  absl::MutexLock lock(mutex_);
  if (!q_inv_big_integer_.has_value()) {
    q_inv_big_integer_.emplace(q_inv_.GetSecret(InsecureSecretKeyAccess::Get()),
                               InsecureSecretKeyAccess::Get());
  }
  return *q_inv_big_integer_;
}

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetPublicKey(
    const RsaSsaPssPublicKey& public_key) {
  public_key_ = public_key;
  return *this;
}

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetPrimeP(
    const RestrictedData& p) {
  p_ = p;
  return *this;
}

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetPrimeQ(
    const RestrictedData& q) {
  q_ = q;
  return *this;
}

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetPrimeExponentP(
    const RestrictedData& dp) {
  dp_ = dp;
  return *this;
}

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetPrimeExponentQ(
    const RestrictedData& dq) {
  dq_ = dq;
  return *this;
}

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetPrivateExponent(
    const RestrictedData& d) {
  d_ = d;
  return *this;
}

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetCrtCoefficient(
    const RestrictedData& q_inv) {
  q_inv_ = q_inv;
  return *this;
}

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetPrimeP(
    const RestrictedBigInteger& p) {
  p_big_integer_ = p;
  return *this;
}

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetPrimeQ(
    const RestrictedBigInteger& q) {
  q_big_integer_ = q;
  return *this;
}

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetPrimeExponentP(
    const RestrictedBigInteger& dp) {
  dp_big_integer_ = dp;
  return *this;
}

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetPrimeExponentQ(
    const RestrictedBigInteger& dq) {
  dq_big_integer_ = dq;
  return *this;
}

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetPrivateExponent(
    const RestrictedBigInteger& d) {
  d_big_integer_ = d;
  return *this;
}

RsaSsaPssPrivateKey::Builder& RsaSsaPssPrivateKey::Builder::SetCrtCoefficient(
    const RestrictedBigInteger& q_inv) {
  q_inv_big_integer_ = q_inv;
  return *this;
}

absl::StatusOr<RsaSsaPssPrivateKey> RsaSsaPssPrivateKey::Builder::Build(
    PartialKeyAccessToken token) {
  if (!public_key_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build without setting the public key");
  }

  bool at_least_one_big_integer =
      p_big_integer_.has_value() || q_big_integer_.has_value() ||
      d_big_integer_.has_value() || dp_big_integer_.has_value() ||
      dq_big_integer_.has_value() || q_inv_big_integer_.has_value();
  bool at_least_one_restricted_data = p_.has_value() || q_.has_value() ||
                                      d_.has_value() || dp_.has_value() ||
                                      dq_.has_value() || q_inv_.has_value();
  bool all_big_integers =
      p_big_integer_.has_value() && q_big_integer_.has_value() &&
      d_big_integer_.has_value() && dp_big_integer_.has_value() &&
      dq_big_integer_.has_value() && q_inv_big_integer_.has_value();
  bool all_restricted_data = p_.has_value() && q_.has_value() &&
                             d_.has_value() && dp_.has_value() &&
                             dq_.has_value() && q_inv_.has_value();

  if (at_least_one_big_integer && at_least_one_restricted_data) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build with a mix of RestrictedData and "
                        "RestrictedBigInteger parameters");
  }

  if (all_big_integers) {
    // p and q won't have any leading zeros if initialized from
    // RestrictedBigInteger.
    RestrictedData p_data(
        p_big_integer_->GetSecretData(InsecureSecretKeyAccess::Get()),
        InsecureSecretKeyAccess::Get());
    RestrictedData q_data(
        q_big_integer_->GetSecretData(InsecureSecretKeyAccess::Get()),
        InsecureSecretKeyAccess::Get());

    absl::StatusOr<RestrictedData> dp_data =
        dp_big_integer_->EncodeWithFixedSize(p_data.size());
    if (!dp_data.ok()) {
      return absl::InvalidArgumentError(
          absl::StrCat("Prime exponent d is too large, expected", p_data.size(),
                       " , got ", dp_big_integer_->SizeInBytes()));
    }
    absl::StatusOr<RestrictedData> dq_data =
        dq_big_integer_->EncodeWithFixedSize(q_data.size());
    if (!dq_data.ok()) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Prime exponent dq is too large, expected", q_data.size(), " , got ",
          dq_big_integer_->SizeInBytes()));
    }
    absl::StatusOr<RestrictedData> d_data = d_big_integer_->EncodeWithFixedSize(
        public_key_->GetModulus(token).SizeInBytes());
    if (!d_data.ok()) {
      return absl::InvalidArgumentError(
          absl::StrCat("Private exponent d has incorrect length: expected ",
                       public_key_->GetModulus(token).SizeInBytes(), " got ",
                       d_big_integer_->SizeInBytes()));
    }

    absl::StatusOr<RestrictedData> q_inv_data =
        q_inv_big_integer_->EncodeWithFixedSize(p_data.size());
    if (!q_inv_data.ok()) {
      return absl::InvalidArgumentError(absl::StrCat(
          "CRT coefficient q_inv has incorrect length: expected ",
          p_data.size(), " got ", q_inv_big_integer_->SizeInBytes()));
    }

    absl::Status key_pair_validation =
        ValidateKeyPair(*public_key_, p_data, q_data, *d_data, *dp_data,
                        *dq_data, *q_inv_data, token);
    if (!key_pair_validation.ok()) {
      return key_pair_validation;
    }
    return RsaSsaPssPrivateKey(*public_key_, p_data, q_data, *dp_data, *dq_data,
                               *d_data, *q_inv_data);
  }

  if (all_restricted_data) {
    absl::Status key_pair_validation = ValidateKeyPair(
        *public_key_, *p_, *q_, *d_, *dp_, *dq_, *q_inv_, token);
    if (!key_pair_validation.ok()) {
      return key_pair_validation;
    }
    return RsaSsaPssPrivateKey(*public_key_, *p_, *q_, *dp_, *dq_, *d_,
                               *q_inv_);
  }

  return absl::Status(absl::StatusCode::kInvalidArgument,
                      "Cannot build without setting all parameters (either "
                      "RestrictedData or RestrictedBigInteger).");
}

absl::StatusOr<RsaSsaPssPrivateKey>
RsaSsaPssPrivateKey::Builder::BuildAllowNonConstantTime(
    PartialKeyAccessToken token) {
  if (!public_key_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build without setting the public key");
  }

  if (p_big_integer_.has_value() || q_big_integer_.has_value() ||
      d_big_integer_.has_value() || dp_big_integer_.has_value() ||
      dq_big_integer_.has_value() || q_inv_big_integer_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "BuildAllowNonConstantTime method can only be used by "
                        "setting RestrictedData fields.");
  }

  if (!(p_.has_value() && q_.has_value() && d_.has_value() && dp_.has_value() &&
        dq_.has_value() && q_inv_.has_value())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "BuildAllowNonConstantTime method requires that all "
                        "RestrictedData fields are set.");
  }

  internal::RsaPrivateKey private_key;
  private_key.n = public_key_->GetModulus(token).GetValue();
  private_key.e = public_key_->GetParameters().GetPublicExponent().GetValue();
  private_key.d = d_->Get(InsecureSecretKeyAccess::Get());
  private_key.p = p_->Get(InsecureSecretKeyAccess::Get());
  private_key.q = q_->Get(InsecureSecretKeyAccess::Get());
  private_key.dp = dp_->Get(InsecureSecretKeyAccess::Get());
  private_key.dq = dq_->Get(InsecureSecretKeyAccess::Get());
  private_key.crt = q_inv_->Get(InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::RsaPrivateKey> adjusted_private_key =
      internal::RsaPrivateKeyAdjustEncodingLengths(private_key);

  if (!adjusted_private_key.ok()) {
    return adjusted_private_key.status();
  }

  p_ = RestrictedData(adjusted_private_key->p, InsecureSecretKeyAccess::Get());
  q_ = RestrictedData(adjusted_private_key->q, InsecureSecretKeyAccess::Get());
  dp_ =
      RestrictedData(adjusted_private_key->dp, InsecureSecretKeyAccess::Get());
  dq_ =
      RestrictedData(adjusted_private_key->dq, InsecureSecretKeyAccess::Get());
  d_ = RestrictedData(adjusted_private_key->d, InsecureSecretKeyAccess::Get());
  q_inv_ =
      RestrictedData(adjusted_private_key->crt, InsecureSecretKeyAccess::Get());

  return Build(token);
}

bool RsaSsaPssPrivateKey::operator==(const Key& other) const {
  const RsaSsaPssPrivateKey* that =
      dynamic_cast<const RsaSsaPssPrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (GetPublicKey() != that->GetPublicKey()) {
    return false;
  }
  if (p_ != that->p_) {
    return false;
  }
  if (q_ != that->q_) {
    return false;
  }
  if (dp_ != that->dp_) {
    return false;
  }
  if (dq_ != that->dq_) {
    return false;
  }
  if (d_ != that->d_) {
    return false;
  }
  return q_inv_ == that->q_inv_;
}

}  // namespace tink
}  // namespace crypto
