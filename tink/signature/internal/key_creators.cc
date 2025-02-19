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

#include "tink/signature/internal/key_creators.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "openssl/mldsa.h"
#include "openssl/slhdsa.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/secret_buffer.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/signature/slh_dsa_private_key.h"
#include "tink/signature/slh_dsa_public_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

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
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid ECDSA curve type.");
  }
}

}  // namespace

absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> CreateMlDsaKey(
    const MlDsaParameters& params, absl::optional<int> id_requirement) {
  if (params.GetInstance() != MlDsaParameters::Instance::kMlDsa65) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only ML-DSA-65 is supported");
  }

  std::string public_key_bytes(MLDSA65_PUBLIC_KEY_BYTES, '\0');
  internal::SecretBuffer private_seed_bytes(MLDSA_SEED_BYTES);
  auto private_key = util::MakeSecretUniquePtr<MLDSA65_private_key>();
  if (!MLDSA65_generate_key(reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
                            private_seed_bytes.data(), private_key.get())) {
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to generate ML-DSA-65 key");
  }

  absl::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
      params, public_key_bytes, id_requirement, GetPartialKeyAccess());

  absl::StatusOr<MlDsaPrivateKey> key = MlDsaPrivateKey::Create(
      *public_key,
      RestrictedData(
          util::internal::AsSecretData(std::move(private_seed_bytes)),
          GetInsecureSecretKeyAccessInternal()),
      GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<MlDsaPrivateKey>(*key);
}

absl::StatusOr<std::unique_ptr<SlhDsaPrivateKey>> CreateSlhDsaKey(
    const SlhDsaParameters& params, absl::optional<int> id_requirement) {
  uint8_t public_key_bytes[SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES];
  uint8_t private_key_bytes[SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES];

  SLHDSA_SHA2_128S_generate_key(public_key_bytes, private_key_bytes);

  absl::StatusOr<SlhDsaPublicKey> public_key = SlhDsaPublicKey::Create(
      params,
      absl::string_view(reinterpret_cast<const char*>(public_key_bytes),
                        SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES),
      id_requirement, GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  absl::StatusOr<SlhDsaPrivateKey> private_key = SlhDsaPrivateKey::Create(
      *public_key,
      RestrictedData(
          absl::string_view(reinterpret_cast<const char*>(private_key_bytes),
                            SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES),
          GetInsecureSecretKeyAccessInternal()),
      GetPartialKeyAccess());
  if (!private_key.ok()) {
    return private_key.status();
  }

  return absl::make_unique<SlhDsaPrivateKey>(*private_key);
}

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

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
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
