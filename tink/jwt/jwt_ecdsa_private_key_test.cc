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

#include "tink/jwt/jwt_ecdsa_private_key.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/jwt/internal/testing/jwt_ecdsa_test_vectors.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::test::HexDecodeOrDie;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::StrEq;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using JwtEcdsaPrivateKeyTest = TestWithParam<jwt_internal::JwtEcdsaTestVector>;

INSTANTIATE_TEST_SUITE_P(JwtEcdsaPrivateKeyTestSuite, JwtEcdsaPrivateKeyTest,
                         ValuesIn(jwt_internal::CreateJwtEcdsaTestVectors()));

TEST_P(JwtEcdsaPrivateKeyTest, CreateSucceeds) {
  const jwt_internal::JwtEcdsaTestVector& test_vector = GetParam();
  const JwtEcdsaPrivateKey& key = test_vector.key;
  const JwtEcdsaPublicKey& public_key = key.GetPublicKey();

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(public_key.GetParameters())
          .SetPublicPoint(public_key.GetPublicPoint(GetPartialKeyAccess()));
  if (public_key.GetIdRequirement().has_value()) {
    builder.SetIdRequirement(*public_key.GetIdRequirement());
  }
  if (public_key.GetParameters().GetKidStrategy() ==
      JwtEcdsaParameters::KidStrategy::kCustom) {
    builder.SetCustomKid(*public_key.GetKid());
  }
  absl::StatusOr<JwtEcdsaPublicKey> created_public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(created_public_key, IsOk());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *created_public_key, key.GetPrivateKey(GetPartialKeyAccess()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(public_key.GetParameters()));
  EXPECT_THAT(private_key->GetKid(), Eq(key.GetKid()));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(key.GetIdRequirement()));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(public_key));
  EXPECT_THAT(private_key->GetPrivateKey(GetPartialKeyAccess()),
              Eq(key.GetPrivateKey(GetPartialKeyAccess())));

  // NOLINTBEGIN(whitespace/line_length) (Formatted when commented in)
  // TINK-PENDING-REMOVAL-IN-3.0.0-START
  EXPECT_THAT(private_key->GetPrivateKeyValue(GetPartialKeyAccess()),
              Eq(RestrictedBigInteger(
                  key.GetPrivateKey(GetPartialKeyAccess())
                      .GetSecret(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  // TINK-PENDING-REMOVAL-IN-3.0.0-END
  // NOLINTEND(whitespace/line_length)
  EXPECT_THAT(private_key->GetPrivateKey(GetPartialKeyAccess()).size(),
              Eq(public_key.GetParameters().GetPrivateKeyLength()));
}

// NOLINTBEGIN(whitespace/line_length) (Formatted when commented in)
// TINK-PENDING-REMOVAL-IN-3.0.0-START
TEST_P(JwtEcdsaPrivateKeyTest, CreateWithRestrictedBigIntegerSucceeds) {
  const jwt_internal::JwtEcdsaTestVector& test_vector = GetParam();
  const JwtEcdsaPrivateKey& key = test_vector.key;
  const JwtEcdsaPublicKey& public_key = key.GetPublicKey();

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(key.GetPrivateKey(GetPartialKeyAccess())
                               .GetSecret(InsecureSecretKeyAccess::Get()),
                           InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key =
      JwtEcdsaPrivateKey::Create(public_key, private_key_value,
                                 GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(public_key.GetParameters()));
  EXPECT_THAT(private_key->GetKid(), Eq(key.GetKid()));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(key.GetIdRequirement()));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(public_key));
  EXPECT_THAT(private_key->GetPrivateKey(GetPartialKeyAccess()),
              Eq(key.GetPrivateKey(GetPartialKeyAccess())));
  EXPECT_THAT(private_key->GetPrivateKeyValue(GetPartialKeyAccess()),
              Eq(private_key_value));
}
// TINK-PENDING-REMOVAL-IN-3.0.0-END
// NOLINTEND(whitespace/line_length)

TEST_P(JwtEcdsaPrivateKeyTest, CreatePrivateKeyAllowNonConstantTimeWorks) {
  const jwt_internal::JwtEcdsaTestVector& test_vector = GetParam();
  const JwtEcdsaPrivateKey& key = test_vector.key;
  const JwtEcdsaPublicKey& public_key = key.GetPublicKey();

  absl::StatusOr<JwtEcdsaPrivateKey> private_key =
      JwtEcdsaPrivateKey::CreateAllowNonConstantTime(
          public_key, key.GetPrivateKey(GetPartialKeyAccess()),
          GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(public_key.GetParameters()));
  EXPECT_THAT(private_key->GetKid(), Eq(key.GetKid()));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(key.GetIdRequirement()));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(public_key));
  EXPECT_THAT(private_key->GetPrivateKey(GetPartialKeyAccess()),
              Eq(key.GetPrivateKey(GetPartialKeyAccess())));
  // NOLINTBEGIN(whitespace/line_length) (Formatted when commented in)
  // TINK-PENDING-REMOVAL-IN-3.0.0-START
  EXPECT_THAT(private_key->GetPrivateKeyValue(GetPartialKeyAccess()),
              Eq(RestrictedBigInteger(
                  key.GetPrivateKey(GetPartialKeyAccess())
                      .GetSecret(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  // TINK-PENDING-REMOVAL-IN-3.0.0-END
  // NOLINTEND(whitespace/line_length)
  EXPECT_THAT(private_key->GetPrivateKey(GetPartialKeyAccess()).size(),
              Eq(public_key.GetParameters().GetPrivateKeyLength()));
}

TEST(JwtEcdsaPrivateKeyTest, CreatePrivateKeyWithOneTooManyBytes) {
  const JwtEcdsaPublicKey& public_key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key.GetPublicKey();

  // Private key with 33 bytes (NIST P-256 takes 32 bytes).
  std::string private_key_bytes = HexDecodeOrDie(
      "ff5356ba39d3d19daab9f2146ae03f5c9b7f2f69a219356b2283977a5e55e5d0b8");
  ASSERT_THAT(private_key_bytes.length(), Eq(33));

  RestrictedData private_key_value =
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      JwtEcdsaPrivateKey::Create(public_key, private_key_value,
                                 GetPartialKeyAccess())
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          StrEq("Private key length 33 is different from expected length 32")));
  EXPECT_THAT(
      JwtEcdsaPrivateKey::CreateAllowNonConstantTime(
          public_key, private_key_value, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument, StrEq("Integer too large")));
}

TEST(JwtEcdsaPrivateKeyTest, CreatePrivateKeyWithOneTooFewBytes) {
  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  std::string public_x = HexDecodeOrDie(
      "5e06e5dc416789b2377a305132455025354d27eec2420c30a0b1658503e14780");
  std::string public_y = HexDecodeOrDie(
      "f43e6af3ef0dabe891693cefc8bf3fe51733a02e19a6fa418a21fc2040ea1b92");
  BigInteger x(public_x);
  BigInteger y(public_y);
  EcPoint public_point(x, y);

  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  // Private key with 31 bytes (NIST P-256 takes 32 bytes).
  std::string private_key_bytes = HexDecodeOrDie(
      "68e0e126325d313dd9cf888e1163c9844cc6f9d9e41ae075338d34e2878cb9");
  ASSERT_THAT(private_key_bytes.length(), Eq(31));

  RestrictedData private_key_value =
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      JwtEcdsaPrivateKey::Create(*public_key, private_key_value,
                                 GetPartialKeyAccess())
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          StrEq("Private key length 31 is different from expected length 32")));
  EXPECT_THAT(JwtEcdsaPrivateKey::CreateAllowNonConstantTime(
                  *public_key, private_key_value, GetPartialKeyAccess())
                  .status(),
              IsOk());
}

TEST(JwtEcdsaPrivateKeyTest, CreateMismatchedKeyPairFails) {
  const JwtEcdsaPublicKey& public_key1 =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key.GetPublicKey();
  const JwtEcdsaPrivateKey& private_key2 =
      jwt_internal::GetJwtEcdsaWycheproofTestVector().key;

  EXPECT_THAT(
      JwtEcdsaPrivateKey::Create(
          public_key1, private_key2.GetPrivateKey(GetPartialKeyAccess()),
          GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid EC key pair")));
}

TEST_P(JwtEcdsaPrivateKeyTest, PrivateKeyEquals) {
  const jwt_internal::JwtEcdsaTestVector& test_vector = GetParam();
  const JwtEcdsaPrivateKey& key = test_vector.key;

  absl::StatusOr<JwtEcdsaPrivateKey> other_private_key =
      JwtEcdsaPrivateKey::Create(key.GetPublicKey(),
                                 key.GetPrivateKey(GetPartialKeyAccess()),
                                 GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(key == *other_private_key);
  EXPECT_TRUE(*other_private_key == key);
  EXPECT_FALSE(key != *other_private_key);
  EXPECT_FALSE(*other_private_key != key);
}

TEST(JwtEcdsaPrivateKeyTest, DifferentPublicKeyNotEqual) {
  const JwtEcdsaPrivateKey& private_key1 =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key;

  absl::StatusOr<JwtEcdsaPublicKey> public_key2 =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(private_key1.GetPublicKey().GetParameters())
          .SetPublicPoint(
              private_key1.GetPublicKey().GetPublicPoint(GetPartialKeyAccess()))
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key2 = JwtEcdsaPrivateKey::Create(
      *public_key2, private_key1.GetPrivateKey(GetPartialKeyAccess()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key2, IsOk());

  EXPECT_TRUE(private_key1 != *private_key2);
  EXPECT_TRUE(*private_key2 != private_key1);
  EXPECT_FALSE(private_key1 == *private_key2);
  EXPECT_FALSE(*private_key2 == private_key1);
}

TEST(JwtEcdsaPrivateKeyTest, DifferentKeyTypesNotEqual) {
  const JwtEcdsaPrivateKey& private_key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key;

  EXPECT_TRUE(private_key != private_key.GetPublicKey());
  EXPECT_TRUE(private_key.GetPublicKey() != private_key);
  EXPECT_FALSE(private_key == private_key.GetPublicKey());
  EXPECT_FALSE(private_key.GetPublicKey() == private_key);
}

TEST(JwtEcdsaPrivateKeyTest, Clone) {
  const JwtEcdsaPrivateKey& key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key;

  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

TEST(JwtEcdsaPrivateKeyTest, CopyConstructor) {
  const JwtEcdsaPrivateKey& key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key;

  JwtEcdsaPrivateKey copy(key);

  EXPECT_THAT(copy, Eq(key));
}

TEST(JwtEcdsaPrivateKeyTest, CopyAssignment) {
  const JwtEcdsaPrivateKey& key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key;
  const JwtEcdsaPrivateKey& other_key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P384)
          .key;

  JwtEcdsaPrivateKey copy = other_key;
  copy = key;

  EXPECT_THAT(copy, Eq(key));
}

TEST(JwtEcdsaPrivateKeyTest, MoveConstructor) {
  JwtEcdsaPrivateKey key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key;

  JwtEcdsaPrivateKey moved(std::move(key));

  EXPECT_THAT(moved, Eq(jwt_internal::GetJwtEcdsaTestVector(
                            subtle::EllipticCurveType::NIST_P256)
                            .key));
}

TEST(JwtEcdsaPrivateKeyTest, MoveAssignment) {
  JwtEcdsaPrivateKey key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key;
  JwtEcdsaPrivateKey other_key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P384)
          .key;

  other_key = std::move(key);

  EXPECT_THAT(other_key, Eq(jwt_internal::GetJwtEcdsaTestVector(
                                subtle::EllipticCurveType::NIST_P256)
                                .key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
