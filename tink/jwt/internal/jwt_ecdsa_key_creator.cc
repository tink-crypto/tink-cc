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

#include "tink/jwt/internal/jwt_ecdsa_key_creator.h"

#include <optional>
#include <string_view>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_private_key.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

absl::StatusOr<subtle::EllipticCurveType> ToSubtleEllipticCurve(
    JwtEcdsaParameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtEcdsaParameters::Algorithm::kEs256:
      return subtle::EllipticCurveType::NIST_P256;
    case JwtEcdsaParameters::Algorithm::kEs384:
      return subtle::EllipticCurveType::NIST_P384;
    case JwtEcdsaParameters::Algorithm::kEs512:
      return subtle::EllipticCurveType::NIST_P521;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid JWT ECDSA algorithm.");
  }
}

}  // namespace

absl::StatusOr<JwtEcdsaPrivateKey> CreateJwtEcdsaPrivateKey(
    const JwtEcdsaParameters& parameters, std::optional<int> id_requirement,
    std::optional<std::string_view> custom_kid) {
  ABSL_ASSIGN_OR_RETURN(subtle::EllipticCurveType curve_type,
                        ToSubtleEllipticCurve(parameters.GetAlgorithm()));

  ABSL_ASSIGN_OR_RETURN(internal::EcKey ec_key, internal::NewEcKey(curve_type));

  EcPoint public_point(BigInteger(ec_key.pub_x), BigInteger(ec_key.pub_y));

  JwtEcdsaPublicKey::Builder pub_builder = JwtEcdsaPublicKey::Builder()
                                               .SetParameters(parameters)
                                               .SetPublicPoint(public_point);
  if (id_requirement.has_value()) {
    pub_builder.SetIdRequirement(*id_requirement);
  }
  if (custom_kid.has_value()) {
    pub_builder.SetCustomKid(*custom_kid);
  }
  ABSL_ASSIGN_OR_RETURN(JwtEcdsaPublicKey public_key,
                        pub_builder.Build(GetPartialKeyAccess()));

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key.priv),
                     GetInsecureSecretKeyAccessInternal());

  return JwtEcdsaPrivateKey::Create(public_key, private_key_value,
                                    GetPartialKeyAccess());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
