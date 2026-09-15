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

#include "tink/hybrid/internal/ecies_key_creator.h"

#include <optional>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_private_key.h"
#include "tink/hybrid/ecies_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

absl::StatusOr<subtle::EllipticCurveType> EnumsToSubtle(
    EciesParameters::CurveType curve_type) {
  switch (curve_type) {
    case EciesParameters::CurveType::kNistP256:
      return subtle::EllipticCurveType::NIST_P256;
    case EciesParameters::CurveType::kNistP384:
      return subtle::EllipticCurveType::NIST_P384;
    case EciesParameters::CurveType::kNistP521:
      return subtle::EllipticCurveType::NIST_P521;
    case EciesParameters::CurveType::kX25519:
      return subtle::EllipticCurveType::CURVE25519;
    default:
      return absl::InvalidArgumentError("Unknown curve type");
  }
}

}  // namespace

absl::StatusOr<crypto::tink::EciesPrivateKey> CreateEciesKey(
    const crypto::tink::EciesParameters& parameters,
    std::optional<int> id_requirement) {
  absl::StatusOr<subtle::EllipticCurveType> curve_type =
      EnumsToSubtle(parameters.GetCurveType());
  if (!curve_type.ok()) return curve_type.status();

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(*curve_type);
  if (!ec_key.ok()) return ec_key.status();

  if (parameters.GetCurveType() == EciesParameters::CurveType::kX25519) {
    absl::StatusOr<EciesPublicKey> public_key =
        EciesPublicKey::CreateForCurveX25519(
            parameters, ec_key->pub_x, id_requirement, GetPartialKeyAccess());
    if (!public_key.ok()) return public_key.status();

    return EciesPrivateKey::CreateForCurveX25519(
        *public_key,
        RestrictedData(ec_key->priv, InsecureSecretKeyAccess::Get()),
        GetPartialKeyAccess());
  }

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(
          parameters,
          EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y)),
          id_requirement, GetPartialKeyAccess());
  if (!public_key.ok()) return public_key.status();

  return EciesPrivateKey::CreateForNistCurve(
      *public_key, RestrictedData(ec_key->priv, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
