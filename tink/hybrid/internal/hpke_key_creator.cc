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

#include "tink/hybrid/internal/hpke_key_creator.h"

#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "openssl/base.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/mlkem_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/xwing_util.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<HpkePrivateKey> CreatePrivateHpkeKey(
    const HpkeParameters& parameters, std::optional<int> id_requirement) {
  switch (parameters.GetKemId()) {
    case HpkeParameters::KemId::kDhkemX25519HkdfSha256: {
      ABSL_ASSIGN_OR_RETURN(std::unique_ptr<internal::X25519Key> key,
                            internal::NewX25519Key());
      std::string_view public_value(
          reinterpret_cast<const char*>(key->public_value), 32);
      ABSL_ASSIGN_OR_RETURN(
          HpkePublicKey public_key,
          HpkePublicKey::Create(parameters, public_value, id_requirement,
                                GetPartialKeyAccess()));
      return HpkePrivateKey::Create(
          public_key,
          RestrictedData(key->private_key, InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
    }
    case HpkeParameters::KemId::kDhkemP256HkdfSha256:
    case HpkeParameters::KemId::kDhkemP384HkdfSha384:
    case HpkeParameters::KemId::kDhkemP521HkdfSha512: {
      subtle::EllipticCurveType curve_type;
      if (parameters.GetKemId() ==
          HpkeParameters::KemId::kDhkemP256HkdfSha256) {
        curve_type = subtle::EllipticCurveType::NIST_P256;
      } else if (parameters.GetKemId() ==
                 HpkeParameters::KemId::kDhkemP384HkdfSha384) {
        curve_type = subtle::EllipticCurveType::NIST_P384;
      } else {
        curve_type = subtle::EllipticCurveType::NIST_P521;
      }
      ABSL_ASSIGN_OR_RETURN(internal::EcKey ec_key,
                            internal::NewEcKey(curve_type));

      ABSL_ASSIGN_OR_RETURN(
          SslUniquePtr<EC_POINT> pub_point,
          internal::GetEcPoint(curve_type, ec_key.pub_x, ec_key.pub_y));

      ABSL_ASSIGN_OR_RETURN(std::string encoded_pub_point,
                            internal::EcPointEncode(
                                curve_type, subtle::EcPointFormat::UNCOMPRESSED,
                                pub_point.get()));

      ABSL_ASSIGN_OR_RETURN(
          HpkePublicKey public_key,
          HpkePublicKey::Create(parameters, encoded_pub_point, id_requirement,
                                GetPartialKeyAccess()));
      return HpkePrivateKey::Create(
          public_key,
          RestrictedData(ec_key.priv, InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
    }
    case HpkeParameters::KemId::kXWing: {
      ABSL_ASSIGN_OR_RETURN(internal::XWingKey key, internal::NewXWingKey());
      std::string_view public_key_bytes(
          reinterpret_cast<const char*>(key.public_key.data()),
          key.public_key.size());
      ABSL_ASSIGN_OR_RETURN(
          HpkePublicKey public_key,
          HpkePublicKey::Create(parameters, public_key_bytes, id_requirement,
                                GetPartialKeyAccess()));
      return HpkePrivateKey::Create(
          public_key,
          RestrictedData(key.private_key, InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
    }
    case HpkeParameters::KemId::kMlKem768:
    case HpkeParameters::KemId::kMlKem1024: {
      internal::MlKemKeySize key_size =
          (parameters.GetKemId() == HpkeParameters::KemId::kMlKem768)
              ? internal::MlKemKeySize::ML_KEM768
              : internal::MlKemKeySize::ML_KEM1024;
      ABSL_ASSIGN_OR_RETURN(internal::MlKemKey key,
                            internal::NewMlKemKey(key_size));
      std::string_view public_key_bytes(
          reinterpret_cast<const char*>(key.public_key.data()),
          key.public_key.size());
      ABSL_ASSIGN_OR_RETURN(
          HpkePublicKey public_key,
          HpkePublicKey::Create(parameters, public_key_bytes, id_requirement,
                                GetPartialKeyAccess()));
      return HpkePrivateKey::Create(
          public_key,
          RestrictedData(key.private_key, InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
    }
    default:
      return absl::InvalidArgumentError("Unsupported KEM type");
  }
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
