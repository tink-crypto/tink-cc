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

#include "tink/jwt/internal/jwt_rsa_ssa_pss_key_creator.h"

#include <optional>
#include <string_view>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "openssl/bn.h"
#include "tink/big_integer.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pss_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<JwtRsaSsaPssPrivateKey> CreatePrivateJwtRsaSsaPssKey(
    const JwtRsaSsaPssParameters& parameters, std::optional<int> id_requirement,
    std::optional<std::string_view> custom_kid) {
  internal::RsaPrivateKey rsa_private_key;
  internal::RsaPublicKey rsa_public_key;
  ABSL_ASSIGN_OR_RETURN(
      internal::SslUniquePtr<BIGNUM> e,
      internal::StringToBignum(parameters.GetPublicExponent().GetValue()));

  ABSL_RETURN_IF_ERROR(
      internal::NewRsaKeyPair(parameters.GetModulusSizeInBits(), e.get(),
                              &rsa_private_key, &rsa_public_key));

  JwtRsaSsaPssPublicKey::Builder pub_builder =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(parameters)
          .SetModulus(BigInteger(rsa_public_key.n));
  if (id_requirement.has_value()) {
    pub_builder.SetIdRequirement(*id_requirement);
  }
  if (custom_kid.has_value()) {
    pub_builder.SetCustomKid(*custom_kid);
  }
  ABSL_ASSIGN_OR_RETURN(JwtRsaSsaPssPublicKey public_key,
                        pub_builder.Build(GetPartialKeyAccess()));

  return JwtRsaSsaPssPrivateKey::Builder()
      .SetPublicKey(public_key)
      .SetPrimeP(RestrictedData(rsa_private_key.p,
                                GetInsecureSecretKeyAccessInternal()))
      .SetPrimeQ(RestrictedData(rsa_private_key.q,
                                GetInsecureSecretKeyAccessInternal()))
      .SetPrimeExponentP(RestrictedData(rsa_private_key.dp,
                                        GetInsecureSecretKeyAccessInternal()))
      .SetPrimeExponentQ(RestrictedData(rsa_private_key.dq,
                                        GetInsecureSecretKeyAccessInternal()))
      .SetPrivateExponent(RestrictedData(rsa_private_key.d,
                                         GetInsecureSecretKeyAccessInternal()))
      .SetCrtCoefficient(RestrictedData(rsa_private_key.crt,
                                        GetInsecureSecretKeyAccessInternal()))
      .Build(GetPartialKeyAccess());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
