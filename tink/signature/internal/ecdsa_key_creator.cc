// Copyright 2024 Google LLC
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

#include "tink/signature/internal/ecdsa_key_creator.h"

#include <memory>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"

#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

absl::StatusOr<subtle::EllipticCurveType> ToSubtleEllipticCurve(
    EcdsaParameters::CurveType curve_type) {
  switch (curve_type) {
    case EcdsaParameters::CurveType::kNistP256:
      return subtle::EllipticCurveType::NIST_P256;
    case EcdsaParameters::CurveType::kNistP384:
      return subtle::EllipticCurveType::NIST_P384;
    case EcdsaParameters::CurveType::kNistP521:
      return subtle::EllipticCurveType::NIST_P521;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid ECDSA curve type.");
  }
}

}  // namespace

absl::StatusOr<std::unique_ptr<EcdsaPrivateKey>> CreateEcdsaKey(
    const EcdsaParameters& params, absl::optional<int> id_requirement) {
  absl::StatusOr<subtle::EllipticCurveType> curve_type =
      ToSubtleEllipticCurve(params.GetCurveType());
  if (!curve_type.ok()) {
    return curve_type.status();
  }

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(*curve_type);
  if (!ec_key.ok()) {
    return ec_key.status();
  }

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      params, public_point, id_requirement, GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     GetInsecureSecretKeyAccessInternal());

  absl::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  if (!private_key.ok()) {
    return private_key.status();
  }

  return absl::make_unique<EcdsaPrivateKey>(*private_key);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
