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
///////////////////////////////////////////////////////////////////////////////

#include "tink/hybrid/internal/testing/ecies_test_util.h"

#include <cstdint>
#include <string>
#include <utility>

#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/testing/ec_test_vectors.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "proto/aes_ctr.pb.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/aes_siv.pb.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/hmac.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

google::crypto::tink::EciesAeadHkdfPrivateKey GetEciesAeadHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type) {
  const internal::EcKey& test_key =
      internal::GetEcKey(util::Enums::ProtoToSubtle(curve_type));

  google::crypto::tink::EciesAeadHkdfPrivateKey ecies_key;
  ecies_key.set_version(0);
  ecies_key.set_key_value(util::SecretDataAsStringView(test_key.priv));
  google::crypto::tink::EciesAeadHkdfPublicKey* public_key =
      ecies_key.mutable_public_key();
  public_key->set_version(0);
  public_key->set_x(test_key.pub_x);
  public_key->set_y(test_key.pub_y);
  google::crypto::tink::EciesAeadHkdfParams* params =
      public_key->mutable_params();
  params->set_ec_point_format(ec_point_format);
  params->mutable_kem_params()->set_curve_type(curve_type);
  params->mutable_kem_params()->set_hkdf_hash_type(hash_type);

  return ecies_key;
}

}  // namespace

google::crypto::tink::EciesAeadHkdfPrivateKey GetEciesAesGcmHkdfTestKey(
    subtle::EllipticCurveType curve_type, subtle::EcPointFormat ec_point_format,
    subtle::HashType hash_type, uint32_t aes_gcm_key_size) {
  return GetEciesAesGcmHkdfTestKey(util::Enums::SubtleToProto(curve_type),
                                   util::Enums::SubtleToProto(ec_point_format),
                                   util::Enums::SubtleToProto(hash_type),
                                   aes_gcm_key_size);
}

google::crypto::tink::EciesAeadHkdfPrivateKey GetEciesAesGcmHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type, uint32_t aes_gcm_key_size) {
  google::crypto::tink::EciesAeadHkdfPrivateKey ecies_key =
      GetEciesAeadHkdfTestKey(curve_type, ec_point_format, hash_type);
  google::crypto::tink::EciesAeadHkdfParams* params =
      ecies_key.mutable_public_key()->mutable_params();

  google::crypto::tink::AesGcmKeyFormat key_format;
  key_format.set_key_size(aes_gcm_key_size);
  google::crypto::tink::KeyTemplate* aead_dem =
      params->mutable_dem_params()->mutable_aead_dem();
  AesGcmKeyManager key_manager;
  std::string dem_key_type = key_manager.get_key_type();
  aead_dem->set_type_url(dem_key_type);
  aead_dem->set_value(key_format.SerializeAsString());
  return ecies_key;
}

google::crypto::tink::EciesAeadHkdfPrivateKey GetEciesAesCtrHmacHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type, uint32_t aes_ctr_key_size,
    uint32_t aes_ctr_iv_size, google::crypto::tink::HashType hmac_hash_type,
    uint32_t hmac_tag_size, uint32_t hmac_key_size) {
  google::crypto::tink::EciesAeadHkdfPrivateKey ecies_key =
      GetEciesAeadHkdfTestKey(curve_type, ec_point_format, hash_type);

  google::crypto::tink::AesCtrHmacAeadKeyFormat key_format;
  google::crypto::tink::AesCtrKeyFormat* aes_ctr_key_format =
      key_format.mutable_aes_ctr_key_format();
  google::crypto::tink::AesCtrParams* aes_ctr_params =
      aes_ctr_key_format->mutable_params();
  aes_ctr_params->set_iv_size(aes_ctr_iv_size);
  aes_ctr_key_format->set_key_size(aes_ctr_key_size);

  google::crypto::tink::HmacKeyFormat* hmac_key_format =
      key_format.mutable_hmac_key_format();
  google::crypto::tink::HmacParams* hmac_params =
      hmac_key_format->mutable_params();
  hmac_params->set_hash(hmac_hash_type);
  hmac_params->set_tag_size(hmac_tag_size);
  hmac_key_format->set_key_size(hmac_key_size);

  google::crypto::tink::EciesAeadHkdfParams* params =
      ecies_key.mutable_public_key()->mutable_params();
  google::crypto::tink::KeyTemplate* aead_dem =
      params->mutable_dem_params()->mutable_aead_dem();

  AesCtrHmacAeadKeyManager key_manager;
  std::string dem_key_type = key_manager.get_key_type();
  aead_dem->set_type_url(dem_key_type);
  aead_dem->set_value(key_format.SerializeAsString());
  return ecies_key;
}

google::crypto::tink::EciesAeadHkdfPrivateKey
GetEciesXChaCha20Poly1305HkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type) {
  google::crypto::tink::EciesAeadHkdfPrivateKey ecies_key =
      GetEciesAeadHkdfTestKey(curve_type, ec_point_format, hash_type);
  google::crypto::tink::EciesAeadHkdfParams* params =
      ecies_key.mutable_public_key()->mutable_params();

  google::crypto::tink::XChaCha20Poly1305KeyFormat key_format;
  google::crypto::tink::KeyTemplate* aead_dem =
      params->mutable_dem_params()->mutable_aead_dem();
  XChaCha20Poly1305KeyManager key_manager;
  std::string dem_key_type = key_manager.get_key_type();
  aead_dem->set_type_url(dem_key_type);
  aead_dem->set_value(key_format.SerializeAsString());
  return ecies_key;
}

google::crypto::tink::EciesAeadHkdfPrivateKey GetEciesAesSivHkdfTestKey(
    google::crypto::tink::EllipticCurveType curve_type,
    google::crypto::tink::EcPointFormat ec_point_format,
    google::crypto::tink::HashType hash_type) {
  google::crypto::tink::EciesAeadHkdfPrivateKey ecies_key =
      GetEciesAeadHkdfTestKey(curve_type, ec_point_format, hash_type);
  google::crypto::tink::EciesAeadHkdfParams* params =
      ecies_key.mutable_public_key()->mutable_params();

  google::crypto::tink::AesSivKeyFormat key_format;
  key_format.set_key_size(64);
  google::crypto::tink::KeyTemplate* aead_dem =
      params->mutable_dem_params()->mutable_aead_dem();
  AesSivKeyManager key_manager;
  std::string dem_key_type = key_manager.get_key_type();
  aead_dem->set_type_url(dem_key_type);
  aead_dem->set_value(key_format.SerializeAsString());
  return ecies_key;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
