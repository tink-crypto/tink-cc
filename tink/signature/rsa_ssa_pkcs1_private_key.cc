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

#include "tink/signature/rsa_ssa_pkcs1_private_key.h"

#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/internal/rsa_util.h"
#include "tink/restricted_data.h"
#include "openssl/opensslv.h"  // To get OPENSSL_IS_BORINGSSL if needed
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"

namespace crypto {
namespace tink {
namespace {

absl::Status ValidateKeyPair(const RsaSsaPkcs1PublicKey& public_key,
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

RsaSsaPkcs1PrivateKey::Builder& RsaSsaPkcs1PrivateKey::Builder::SetPublicKey(
    const RsaSsaPkcs1PublicKey& public_key) {
  public_key_ = public_key;
  return *this;
}

RsaSsaPkcs1PrivateKey::Builder& RsaSsaPkcs1PrivateKey::Builder::SetPrimeP(
    const RestrictedData& p) {
  p_ = p;
  return *this;
}

RsaSsaPkcs1PrivateKey::Builder& RsaSsaPkcs1PrivateKey::Builder::SetPrimeQ(
    const RestrictedData& q) {
  q_ = q;
  return *this;
}

RsaSsaPkcs1PrivateKey::Builder&
RsaSsaPkcs1PrivateKey::Builder::SetPrimeExponentP(const RestrictedData& dp) {
  dp_ = dp;
  return *this;
}

RsaSsaPkcs1PrivateKey::Builder&
RsaSsaPkcs1PrivateKey::Builder::SetPrimeExponentQ(const RestrictedData& dq) {
  dq_ = dq;
  return *this;
}

RsaSsaPkcs1PrivateKey::Builder&
RsaSsaPkcs1PrivateKey::Builder::SetPrivateExponent(const RestrictedData& d) {
  d_ = d;
  return *this;
}

RsaSsaPkcs1PrivateKey::Builder&
RsaSsaPkcs1PrivateKey::Builder::SetCrtCoefficient(const RestrictedData& q_inv) {
  q_inv_ = q_inv;
  return *this;
}

absl::StatusOr<RsaSsaPkcs1PrivateKey> RsaSsaPkcs1PrivateKey::Builder::Build(
    PartialKeyAccessToken token) {
  if (!public_key_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build without setting the public key");
  }

  if (!p_.has_value() || !q_.has_value() || !d_.has_value() ||
      !dp_.has_value() || !dq_.has_value() || !q_inv_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build without setting all parameters");
  }

  absl::Status key_pair_validation =
      ValidateKeyPair(*public_key_, *p_, *q_, *d_, *dp_, *dq_, *q_inv_, token);
  if (!key_pair_validation.ok()) {
    return key_pair_validation;
  }
  return RsaSsaPkcs1PrivateKey(*public_key_, *p_, *q_, *dp_, *dq_, *d_,
                               *q_inv_);
}

absl::StatusOr<RsaSsaPkcs1PrivateKey>
RsaSsaPkcs1PrivateKey::Builder::BuildAllowNonConstantTime(
    PartialKeyAccessToken token) {
  if (!public_key_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build without setting the public key");
  }

  if (!p_.has_value() || !q_.has_value() || !d_.has_value() ||
      !dp_.has_value() || !dq_.has_value() || !q_inv_.has_value()) {
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

bool RsaSsaPkcs1PrivateKey::operator==(const Key& other) const {
  const RsaSsaPkcs1PrivateKey* that =
      dynamic_cast<const RsaSsaPkcs1PrivateKey*>(&other);
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
