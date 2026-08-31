// Copyright 2017 Google LLC
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

#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/testing/ec_test_vectors.h"
#include "tink/subtle/common_enums.h"
#include "proto/aes_eax.pb.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::google::crypto::tink::EciesAeadHkdfParams;
using ::google::crypto::tink::EciesAeadHkdfPublicKey;
using ::google::crypto::tink::EciesHkdfKemParams;
using ::google::crypto::tink::EcPointFormat;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;

TEST(EciesAeadHkdfPublicKeyManagerTest, Basics) {
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().get_version(), Eq(0));
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(
      EciesAeadHkdfPublicKeyManager().get_key_type(),
      Eq("type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey"));
}

TEST(EciesAeadHkdfPublicKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(
      EciesAeadHkdfPublicKeyManager().ValidateKey(EciesAeadHkdfPublicKey()),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

EciesAeadHkdfPublicKey CreatePublicKey() {
  EciesAeadHkdfPublicKey public_key;
  public_key.set_version(0);
  const internal::EcKey& ec_key =
      internal::GetEcKey(subtle::EllipticCurveType::NIST_P256);
  public_key.set_x(ec_key.pub_x);
  public_key.set_y(ec_key.pub_y);
  EciesAeadHkdfParams* params = public_key.mutable_params();
  params->set_ec_point_format(EcPointFormat::UNCOMPRESSED);
  params->mutable_dem_params()->mutable_aead_dem()->CopyFrom(
      AeadKeyTemplates::Aes128Gcm());
  EciesHkdfKemParams* kem_params = params->mutable_kem_params();
  kem_params->set_curve_type(EllipticCurveType::NIST_P256);
  kem_params->set_hkdf_hash_type(HashType::SHA256);
  kem_params->set_hkdf_salt("");
  return public_key;
}

TEST(EciesAeadHkdfPublicKeyManagerTest, ValidateParams) {
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().ValidateParams(
                  CreatePublicKey().params()),
              IsOk());
}

TEST(EciesAeadHkdfPublicKeyManagerTest, ValidateKeyNoPoint) {
  EciesAeadHkdfParams params = CreatePublicKey().params();
  params.set_ec_point_format(EcPointFormat::UNKNOWN_FORMAT);
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPublicKeyManagerTest, ValidateKeyNoDem) {
  EciesAeadHkdfParams params = CreatePublicKey().params();
  params.mutable_dem_params()->clear_aead_dem();
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPublicKeyManagerTest, ValidateKeyNoKemCurve) {
  EciesAeadHkdfParams params = CreatePublicKey().params();
  params.mutable_kem_params()->set_curve_type(EllipticCurveType::UNKNOWN_CURVE);
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPublicKeyManagerTest, ValidateKeyNoKemHash) {
  EciesAeadHkdfParams params = CreatePublicKey().params();
  params.mutable_kem_params()->set_hkdf_hash_type(HashType::UNKNOWN_HASH);
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesAeadHkdfPublicKeyManagerTest, ValidateGeneratedKey) {
  EXPECT_THAT(EciesAeadHkdfPublicKeyManager().ValidateKey(CreatePublicKey()),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
