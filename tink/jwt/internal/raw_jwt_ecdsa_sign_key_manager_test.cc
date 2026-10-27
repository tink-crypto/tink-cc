// Copyright 2021 Google LLC
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

#include "tink/jwt/internal/raw_jwt_ecdsa_sign_key_manager.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::JwtEcdsaKeyFormat;
using ::google::crypto::tink::JwtEcdsaPrivateKey;
using ::google::crypto::tink::JwtEcdsaPublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::Not;
using ::testing::SizeIs;

namespace {

const EcdsaPrivateKey& GetTestVectorPrivateKey(
    EcdsaParameters::CurveType curve_type,
    EcdsaParameters::HashType hash_type) {
  const internal::SignatureTestVector& test_vector =
      internal::GetEcdsaTestVector(
          curve_type, hash_type, EcdsaParameters::SignatureEncoding::kIeeeP1363,
          EcdsaParameters::Variant::kNoPrefix);
  const auto* private_key = dynamic_cast<const EcdsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ABSL_CHECK_NE(private_key, nullptr);
  return *private_key;
}

JwtEcdsaPrivateKey ToJwtEcdsaPrivateKey(const EcdsaPrivateKey& private_key,
                                        JwtEcdsaAlgorithm algorithm) {
  JwtEcdsaPrivateKey key;
  key.set_version(0);
  key.set_key_value(private_key.GetPrivateKey(GetPartialKeyAccess())
                        .GetSecret(InsecureSecretKeyAccess::Get()));
  JwtEcdsaPublicKey* public_key = key.mutable_public_key();
  public_key->set_version(0);
  public_key->set_algorithm(algorithm);
  public_key->set_x(std::string(private_key.GetPublicKey()
                                    .GetPublicPoint(GetPartialKeyAccess())
                                    .GetX()
                                    .GetValue()));
  public_key->set_y(std::string(private_key.GetPublicKey()
                                    .GetPublicPoint(GetPartialKeyAccess())
                                    .GetY()
                                    .GetValue()));
  return key;
}

TEST(RawJwtEcdsaSignKeyManagerTest, Basic) {
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().get_version(), Eq(0));
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey"));
}

TEST(RawJwtEcdsaSignKeyManagerTest, ValidateEmptyKeyFormat) {
  EXPECT_THAT(
      RawJwtEcdsaSignKeyManager().ValidateKeyFormat(JwtEcdsaKeyFormat()),
      Not(IsOk()));
}

JwtEcdsaKeyFormat CreateValidEs256KeyFormat() {
  JwtEcdsaKeyFormat key_format;
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES256);
  return key_format;
}

TEST(RawJwtEcdsaSignKeyManagerTest, ValidateKeyFormat) {
  JwtEcdsaKeyFormat format = CreateValidEs256KeyFormat();
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().ValidateKeyFormat(format), IsOk());
}

TEST(RawJwtEcdsaSignKeyManagerTest, ValidateKeyFormatUnknownAlgorithm) {
  JwtEcdsaKeyFormat key_format = CreateValidEs256KeyFormat();
  key_format.set_algorithm(JwtEcdsaAlgorithm::ES_UNKNOWN);
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().ValidateKeyFormat(key_format),
              Not(IsOk()));
}

TEST(RawJwtEcdsaSignKeyManagerTest, CreateKey) {
  JwtEcdsaKeyFormat format = CreateValidEs256KeyFormat();
  absl::StatusOr<JwtEcdsaPrivateKey> key =
      RawJwtEcdsaSignKeyManager().CreateKey(format);
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->version(), Eq(0));

  EXPECT_THAT(key->public_key().version(), Eq(key->version()));
  EXPECT_THAT(key->public_key().algorithm(),
              Eq(format.algorithm()));

  EXPECT_THAT(key->public_key().x(), SizeIs(Gt(0)));
  EXPECT_THAT(key->public_key().y(), SizeIs(Gt(0)));

  EXPECT_THAT(key->key_value(), SizeIs(Gt(0)));
}

TEST(RawJwtEcdsaSignKeyManagerTest, CreateKeyValid) {
  JwtEcdsaKeyFormat format = CreateValidEs256KeyFormat();
  absl::StatusOr<JwtEcdsaPrivateKey> key =
      RawJwtEcdsaSignKeyManager().CreateKey(format);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().ValidateKey(*key),
              IsOk());
}

JwtEcdsaPrivateKey CreateValidEs256Key() {
  return ToJwtEcdsaPrivateKey(
      GetTestVectorPrivateKey(EcdsaParameters::CurveType::kNistP256,
                              EcdsaParameters::HashType::kSha256),
      JwtEcdsaAlgorithm::ES256);
}

TEST(RawJwtEcdsaSignKeyManagerTest, ValidateKey) {
  JwtEcdsaPrivateKey key = CreateValidEs256Key();
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().ValidateKey(key), IsOk());
}

TEST(RawJwtEcdsaSignKeyManagerTest, ValidateKeyUnknownAlgorithm) {
  JwtEcdsaPrivateKey key = CreateValidEs256Key();
  key.mutable_public_key()->set_algorithm(JwtEcdsaAlgorithm::ES_UNKNOWN);
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(RawJwtEcdsaSignKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RawJwtEcdsaSignKeyManagerTest, GetPublicKey) {
  JwtEcdsaPrivateKey key = CreateValidEs256Key();
  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      RawJwtEcdsaSignKeyManager().GetPublicKey(key);

  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->version(), Eq(key.public_key().version()));
  EXPECT_THAT(public_key->algorithm(),
              Eq(key.public_key().algorithm()));

  EXPECT_THAT(public_key->x(), Eq(key.public_key().x()));
  EXPECT_THAT(public_key->y(), Eq(key.public_key().y()));
}

TEST(RawJwtEcdsaSignKeyManagerTest, Create) {
  const EcdsaPrivateKey& ecdsa_private_key =
      GetTestVectorPrivateKey(EcdsaParameters::CurveType::kNistP256,
                              EcdsaParameters::HashType::kSha256);
  JwtEcdsaPrivateKey private_key =
      ToJwtEcdsaPrivateKey(ecdsa_private_key, JwtEcdsaAlgorithm::ES256);

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      RawJwtEcdsaSignKeyManager().GetPrimitive<PublicKeySign>(private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>>
      direct_verifier =
          subtle::EcdsaVerifyBoringSsl::New(ecdsa_private_key.GetPublicKey());
  ASSERT_THAT(direct_verifier, IsOk());

  std::string message = "Some message";
  absl::StatusOr<std::string> sig = (*signer)->Sign(message);
  ASSERT_THAT(sig, IsOk());
  EXPECT_THAT((*direct_verifier)->Verify(*sig, message), IsOk());
}

TEST(RawJwtEcdsaSignKeyManagerTest, CreateDifferentKey) {
  JwtEcdsaPrivateKey private_key = CreateValidEs256Key();
  const EcdsaPrivateKey& different_ecdsa_private_key =
      GetTestVectorPrivateKey(EcdsaParameters::CurveType::kNistP384,
                              EcdsaParameters::HashType::kSha384);

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      RawJwtEcdsaSignKeyManager().GetPrimitive<PublicKeySign>(private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<subtle::EcdsaVerifyBoringSsl>>
      direct_verifier = subtle::EcdsaVerifyBoringSsl::New(
          different_ecdsa_private_key.GetPublicKey());
  ASSERT_THAT(direct_verifier, IsOk());

  std::string message = "Some message";
  absl::StatusOr<std::string> sig = (*signer)->Sign(message);
  ASSERT_THAT(sig, IsOk());
  EXPECT_THAT((*direct_verifier)->Verify(*sig, message), Not(IsOk()));
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
