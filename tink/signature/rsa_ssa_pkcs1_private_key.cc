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

#include <memory>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_big_integer.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::CallWithCoreDumpProtection;

absl::Status ValidateKeyPair(const RsaSsaPkcs1PublicKey& public_key,
                             const RestrictedData& p, const RestrictedData& q,
                             const RestrictedData& d, const RestrictedData& dp,
                             const RestrictedData& dq,
                             const RestrictedData& q_inv,
                             PartialKeyAccessToken token) {
  const BigInteger& public_exponent =
      public_key.GetParameters().GetPublicExponent();
  const BigInteger& modulus = public_key.GetModulus(token);

  internal::SslUniquePtr<RSA> rsa(RSA_new());
  if (rsa.get() == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Internal RSA allocation error");
  }

  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
      internal::StringToBignum(modulus.GetValue());
  if (!n.ok()) {
    return n.status();
  }

  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> e =
      internal::StringToBignum(public_exponent.GetValue());
  if (!e.ok()) {
    return e.status();
  }

  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> d_bn =
      internal::StringToBignum(d.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!d_bn.ok()) {
    return d_bn.status();
  }

  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> p_bn =
      internal::StringToBignum(p.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!p_bn.ok()) {
    return p_bn.status();
  }
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> q_bn =
      internal::StringToBignum(q.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!q_bn.ok()) {
    return q_bn.status();
  }

  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> dp_bn =
      internal::StringToBignum(dp.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!dp_bn.ok()) {
    return dp_bn.status();
  }
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> dq_bn =
      internal::StringToBignum(dq.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!dq_bn.ok()) {
    return dq_bn.status();
  }
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> q_inv_bn =
      internal::StringToBignum(q_inv.GetSecret(InsecureSecretKeyAccess::Get()));
  if (!q_inv_bn.ok()) {
    return q_inv_bn.status();
  }

  return CallWithCoreDumpProtection([&]() -> absl::Status {
    /// Checks for size and leading zeros.
    const absl::string_view p_sd = p.GetSecret(InsecureSecretKeyAccess::Get());
    if (p_sd.size() > 1 && p_sd[0] == 0) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Prime factor p has leading zeros");
    }
    const absl::string_view q_sd = q.GetSecret(InsecureSecretKeyAccess::Get());
    if (q_sd.size() > 1 && q_sd[0] == 0) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Prime factor q has leading zeros");
    }

    if (dp.size() != p.size()) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Prime exponent dp has incorrect length: expected ",
                       p.size(), " got ", dp.size()));
    }

    if (dq.size() != q.size()) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Prime exponent dq has incorrect length: expected ",
                       q.size(), " got ", dq.size()));
    }

    int modulus_size_in_bytes =
        (public_key.GetParameters().GetModulusSizeInBits() + 7) / 8;
    if (d.size() != modulus_size_in_bytes) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Private exponent d has incorrect length: expected ",
                       modulus_size_in_bytes, " got ", d.size()));
    }

    if (q_inv.size() != p.size()) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("CRT coefficient has incorrect length: expected ",
                       p.size(), " got ", q_inv.size()));
    }

    // Build RSA key from the given values.  The RSA object takes ownership
    // of the given values after the call.
    if (RSA_set0_key(rsa.get(), n->release(), e->release(), d_bn->release()) !=
            1 ||
        RSA_set0_factors(rsa.get(), p_bn->release(), q_bn->release()) != 1 ||
        RSA_set0_crt_params(rsa.get(), dp_bn->release(), dq_bn->release(),
                            q_inv_bn->release()) != 1) {
      return absl::Status(absl::StatusCode::kInternal,
                          "Internal RSA key loading error");
    }

    // Validate key.
    int check_key_status = RSA_check_key(rsa.get());
    if (check_key_status == 0) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "RSA key pair is not valid");
    }

    if (check_key_status == -1) {
      return absl::Status(absl::StatusCode::kInternal,
                          "An error ocurred while checking the key");
    }

#ifdef OPENSSL_IS_BORINGSSL
    if (RSA_check_fips(rsa.get()) == 0) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "RSA key pair is not valid in FIPS mode");
    }
#endif
    return absl::OkStatus();
  });
}

}  // namespace

RsaSsaPkcs1PrivateKey& RsaSsaPkcs1PrivateKey::operator=(
    const RsaSsaPkcs1PrivateKey& other) {
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

RsaSsaPkcs1PrivateKey::Builder& RsaSsaPkcs1PrivateKey::Builder::SetPublicKey(
    const RsaSsaPkcs1PublicKey& public_key) {
  public_key_ = public_key;
  return *this;
}

const RestrictedBigInteger& RsaSsaPkcs1PrivateKey::GetPrimeP(
    PartialKeyAccessToken token) const {
  absl::MutexLock lock(mutex_);
  if (!p_big_integer_.has_value()) {
    p_big_integer_ =
        RestrictedBigInteger(p_.GetSecret(InsecureSecretKeyAccess::Get()),
                             InsecureSecretKeyAccess::Get());
  }
  return *p_big_integer_;
}

const RestrictedBigInteger& RsaSsaPkcs1PrivateKey::GetPrimeQ(
    PartialKeyAccessToken token) const {
  absl::MutexLock lock(mutex_);
  if (!q_big_integer_.has_value()) {
    q_big_integer_ =
        RestrictedBigInteger(q_.GetSecret(InsecureSecretKeyAccess::Get()),
                             InsecureSecretKeyAccess::Get());
  }
  return *q_big_integer_;
}

const RestrictedBigInteger& RsaSsaPkcs1PrivateKey::GetPrivateExponent() const {
  absl::MutexLock lock(mutex_);
  if (!d_big_integer_.has_value()) {
    d_big_integer_ =
        RestrictedBigInteger(d_.GetSecret(InsecureSecretKeyAccess::Get()),
                             InsecureSecretKeyAccess::Get());
  }
  return *d_big_integer_;
}

const RestrictedBigInteger& RsaSsaPkcs1PrivateKey::GetPrimeExponentP() const {
  absl::MutexLock lock(mutex_);
  if (!dp_big_integer_.has_value()) {
    dp_big_integer_ =
        RestrictedBigInteger(dp_.GetSecret(InsecureSecretKeyAccess::Get()),
                             InsecureSecretKeyAccess::Get());
  }
  return *dp_big_integer_;
}

const RestrictedBigInteger& RsaSsaPkcs1PrivateKey::GetPrimeExponentQ() const {
  absl::MutexLock lock(mutex_);
  if (!dq_big_integer_.has_value()) {
    dq_big_integer_ =
        RestrictedBigInteger(dq_.GetSecret(InsecureSecretKeyAccess::Get()),
                             InsecureSecretKeyAccess::Get());
  }
  return *dq_big_integer_;
}

const RestrictedBigInteger& RsaSsaPkcs1PrivateKey::GetCrtCoefficient() const {
  absl::MutexLock lock(mutex_);
  if (!q_inv_big_integer_.has_value()) {
    q_inv_big_integer_ =
        RestrictedBigInteger(q_inv_.GetSecret(InsecureSecretKeyAccess::Get()),
                             InsecureSecretKeyAccess::Get());
  }
  return *q_inv_big_integer_;
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

RsaSsaPkcs1PrivateKey::Builder& RsaSsaPkcs1PrivateKey::Builder::SetPrimeP(
    const RestrictedBigInteger& p) {
  p_big_integer_ = p;
  return *this;
}

RsaSsaPkcs1PrivateKey::Builder& RsaSsaPkcs1PrivateKey::Builder::SetPrimeQ(
    const RestrictedBigInteger& q) {
  q_big_integer_ = q;
  return *this;
}

RsaSsaPkcs1PrivateKey::Builder&
RsaSsaPkcs1PrivateKey::Builder::SetPrimeExponentP(
    const RestrictedBigInteger& dp) {
  dp_big_integer_ = dp;
  return *this;
}

RsaSsaPkcs1PrivateKey::Builder&
RsaSsaPkcs1PrivateKey::Builder::SetPrimeExponentQ(
    const RestrictedBigInteger& dq) {
  dq_big_integer_ = dq;
  return *this;
}

RsaSsaPkcs1PrivateKey::Builder&
RsaSsaPkcs1PrivateKey::Builder::SetPrivateExponent(
    const RestrictedBigInteger& d) {
  d_big_integer_ = d;
  return *this;
}

RsaSsaPkcs1PrivateKey::Builder&
RsaSsaPkcs1PrivateKey::Builder::SetCrtCoefficient(
    const RestrictedBigInteger& q_inv) {
  q_inv_big_integer_ = q_inv;
  return *this;
}

absl::StatusOr<RsaSsaPkcs1PrivateKey> RsaSsaPkcs1PrivateKey::Builder::Build(
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
      return absl::InvalidArgumentError(absl::StrCat(
          "Prime exponent dp is too large, expected", p_data.size(), " , got ",
          dp_big_integer_->SizeInBytes()));
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
    return RsaSsaPkcs1PrivateKey(*public_key_, p_data, q_data, *dp_data,
                                 *dq_data, *d_data, *q_inv_data);
  }

  if (all_restricted_data) {
    absl::Status key_pair_validation = ValidateKeyPair(
        *public_key_, *p_, *q_, *d_, *dp_, *dq_, *q_inv_, token);
    if (!key_pair_validation.ok()) {
      return key_pair_validation;
    }
    return RsaSsaPkcs1PrivateKey(*public_key_, *p_, *q_, *dp_, *dq_, *d_,
                                 *q_inv_);
  }

  return absl::Status(absl::StatusCode::kInvalidArgument,
                      "Cannot build without setting all parameters (either "
                      "RestrictedData or RestrictedBigInteger).");
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
