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

#include "tink/signature/internal/rsa_ssa_pkcs1_key_creator.h"

#include <memory>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "openssl/bn.h"
#include "tink/big_integer.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<RsaSsaPkcs1PrivateKey>> CreateRsaSsaPkcs1Key(
    const RsaSsaPkcs1Parameters& params, absl::optional<int> id_requirement) {
  internal::RsaPrivateKey rsa_private_key;
  internal::RsaPublicKey rsa_public_key;
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> e =
      internal::StringToBignum(params.GetPublicExponent().GetValue());
  if (!e.ok()) {
    return e.status();
  }
  absl::Status status =
      internal::NewRsaKeyPair(params.GetModulusSizeInBits(), e->get(),
                              &rsa_private_key, &rsa_public_key);
  if (!status.ok()) {
    return status;
  }
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(params, BigInteger(rsa_public_key.n),
                                   id_requirement, GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedData(rsa_private_key.p,
                                    GetInsecureSecretKeyAccessInternal()))
          .SetPrimeQ(RestrictedData(rsa_private_key.q,
                                    GetInsecureSecretKeyAccessInternal()))
          .SetPrimeExponentP(RestrictedData(
              rsa_private_key.dp, GetInsecureSecretKeyAccessInternal()))
          .SetPrimeExponentQ(RestrictedData(
              rsa_private_key.dq, GetInsecureSecretKeyAccessInternal()))
          .SetPrivateExponent(RestrictedData(
              rsa_private_key.d, GetInsecureSecretKeyAccessInternal()))
          .SetCrtCoefficient(RestrictedData(
              rsa_private_key.crt, GetInsecureSecretKeyAccessInternal()))
          .Build(GetPartialKeyAccess());
  if (!private_key.ok()) {
    return private_key.status();
  }
  return std::make_unique<RsaSsaPkcs1PrivateKey>(*private_key);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
