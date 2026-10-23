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

#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"

#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"

namespace crypto {
namespace tink {

JwtRsaSsaPkcs1PrivateKey::Builder&
JwtRsaSsaPkcs1PrivateKey::Builder::SetPublicKey(
    const JwtRsaSsaPkcs1PublicKey& public_key) {
  public_key_ = public_key;
  return *this;
}

JwtRsaSsaPkcs1PrivateKey::Builder& JwtRsaSsaPkcs1PrivateKey::Builder::SetPrimeP(
    const RestrictedData& p) {
  p_ = p;
  return *this;
}

JwtRsaSsaPkcs1PrivateKey::Builder& JwtRsaSsaPkcs1PrivateKey::Builder::SetPrimeQ(
    const RestrictedData& q) {
  q_ = q;
  return *this;
}

JwtRsaSsaPkcs1PrivateKey::Builder&
JwtRsaSsaPkcs1PrivateKey::Builder::SetPrimeExponentP(const RestrictedData& dp) {
  dp_ = dp;
  return *this;
}

JwtRsaSsaPkcs1PrivateKey::Builder&
JwtRsaSsaPkcs1PrivateKey::Builder::SetPrimeExponentQ(const RestrictedData& dq) {
  dq_ = dq;
  return *this;
}

JwtRsaSsaPkcs1PrivateKey::Builder&
JwtRsaSsaPkcs1PrivateKey::Builder::SetPrivateExponent(const RestrictedData& d) {
  d_ = d;
  return *this;
}

JwtRsaSsaPkcs1PrivateKey::Builder&
JwtRsaSsaPkcs1PrivateKey::Builder::SetCrtCoefficient(
    const RestrictedData& q_inv) {
  q_inv_ = q_inv;
  return *this;
}

absl::StatusOr<JwtRsaSsaPkcs1PrivateKey>
JwtRsaSsaPkcs1PrivateKey::Builder::Build(PartialKeyAccessToken token) {
  if (!public_key_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build without setting the public key");
  }
  RsaSsaPkcs1PrivateKey::Builder builder;
  builder.SetPublicKey(public_key_->GetRsaSsaPkcs1PublicKey(token));
  if (p_.has_value()) {
    builder.SetPrimeP(*p_);
  }
  if (q_.has_value()) {
    builder.SetPrimeQ(*q_);
  }
  if (d_.has_value()) {
    builder.SetPrivateExponent(*d_);
  }
  if (dp_.has_value()) {
    builder.SetPrimeExponentP(*dp_);
  }
  if (dq_.has_value()) {
    builder.SetPrimeExponentQ(*dq_);
  }
  if (q_inv_.has_value()) {
    builder.SetCrtCoefficient(*q_inv_);
  }
  ABSL_ASSIGN_OR_RETURN(RsaSsaPkcs1PrivateKey rsa_ssa_pkcs1_private_key,
                        builder.Build(token));
  return JwtRsaSsaPkcs1PrivateKey(*public_key_,
                                  std::move(rsa_ssa_pkcs1_private_key));
}

absl::StatusOr<JwtRsaSsaPkcs1PrivateKey>
JwtRsaSsaPkcs1PrivateKey::Builder::BuildAllowNonConstantTime(
    PartialKeyAccessToken token) {
  if (!public_key_.has_value()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot build without setting the public key");
  }
  RsaSsaPkcs1PrivateKey::Builder builder;
  builder.SetPublicKey(public_key_->GetRsaSsaPkcs1PublicKey(token));
  if (p_.has_value()) {
    builder.SetPrimeP(*p_);
  }
  if (q_.has_value()) {
    builder.SetPrimeQ(*q_);
  }
  if (d_.has_value()) {
    builder.SetPrivateExponent(*d_);
  }
  if (dp_.has_value()) {
    builder.SetPrimeExponentP(*dp_);
  }
  if (dq_.has_value()) {
    builder.SetPrimeExponentQ(*dq_);
  }
  if (q_inv_.has_value()) {
    builder.SetCrtCoefficient(*q_inv_);
  }
  ABSL_ASSIGN_OR_RETURN(RsaSsaPkcs1PrivateKey rsa_ssa_pkcs1_private_key,
                        builder.BuildAllowNonConstantTime(token));
  return JwtRsaSsaPkcs1PrivateKey(*public_key_,
                                  std::move(rsa_ssa_pkcs1_private_key));
}

bool JwtRsaSsaPkcs1PrivateKey::operator==(const Key& other) const {
  const JwtRsaSsaPkcs1PrivateKey* that =
      dynamic_cast<const JwtRsaSsaPkcs1PrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }

  return public_key_ == that->public_key_ &&
         rsa_ssa_pkcs1_private_key_ == that->rsa_ssa_pkcs1_private_key_;
}

}  // namespace tink
}  // namespace crypto
