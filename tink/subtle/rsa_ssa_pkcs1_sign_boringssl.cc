// Copyright 2018 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

#include "tink/subtle/rsa_ssa_pkcs1_sign_boringssl.h"

#include <memory>
#include <optional>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/rsa_util.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/restricted_data.h"
#include "tink/signature/internal/rsa_ssa_pkcs1_sign_boringssl.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

absl::StatusOr<RsaSsaPkcs1Parameters::HashType> ToParametersHashType(
    HashType hash_type) {
  switch (hash_type) {
    case SHA256:
      return RsaSsaPkcs1Parameters::HashType::kSha256;
    case SHA384:
      return RsaSsaPkcs1Parameters::HashType::kSha384;
    case SHA512:
      return RsaSsaPkcs1Parameters::HashType::kSha512;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported hash: ", hash_type));
  }
}

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeySign>> RsaSsaPkcs1SignBoringSsl::New(
    const RsaSsaPkcs1PrivateKey& key) {
  return internal::NewRsaSsaPkcs1SignBoringSsl(key);
}

absl::StatusOr<std::unique_ptr<PublicKeySign>> RsaSsaPkcs1SignBoringSsl::New(
    const internal::RsaPrivateKey& private_key,
    const internal::RsaSsaPkcs1Params& params) {
  ABSL_RETURN_IF_ERROR(
      internal::CheckFipsCompatibility<RsaSsaPkcs1SignBoringSsl>());
  ABSL_ASSIGN_OR_RETURN(RsaSsaPkcs1Parameters::HashType hash_type,
                        ToParametersHashType(params.hash_type));
  BigInteger modulus(private_key.n);
  ABSL_ASSIGN_OR_RETURN(
      RsaSsaPkcs1Parameters parameters,
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(modulus.SizeInBytes() * 8)
          .SetPublicExponent(BigInteger(private_key.e))
          .SetHashType(hash_type)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build());
  ABSL_ASSIGN_OR_RETURN(
      RsaSsaPkcs1PublicKey public_key,
      RsaSsaPkcs1PublicKey::Create(parameters, modulus,
                                   /*id_requirement=*/std::nullopt,
                                   GetPartialKeyAccess()));
  ABSL_ASSIGN_OR_RETURN(
      RsaSsaPkcs1PrivateKey key,
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(
              RestrictedData(private_key.p, InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(
              RestrictedData(private_key.q, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(
              RestrictedData(private_key.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(
              RestrictedData(private_key.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(
              RestrictedData(private_key.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(
              RestrictedData(private_key.crt, InsecureSecretKeyAccess::Get()))
          .BuildAllowNonConstantTime(GetPartialKeyAccess()));
  return New(key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
