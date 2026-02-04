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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::StrEq;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  JwtEcdsaParameters::KidStrategy kid_strategy;
  JwtEcdsaParameters::Algorithm algorithm;
  subtle::EllipticCurveType curve;
  absl::optional<std::string> custom_kid;
  absl::optional<int> id_requirement;
  absl::optional<std::string> expected_kid;
};

using JwtEcdsaPrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    JwtEcdsaPrivateKeyTestSuite, JwtEcdsaPrivateKeyTest,
    Values(TestCase{JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
                    JwtEcdsaParameters::Algorithm::kEs256,
                    subtle::EllipticCurveType::NIST_P256,
                    /*custom_kid=*/absl::nullopt, /*id_requirement=*/123,
                    /*expected_kid=*/"AAAAew"},
           TestCase{JwtEcdsaParameters::KidStrategy::kCustom,
                    JwtEcdsaParameters::Algorithm::kEs384,
                    subtle::EllipticCurveType::NIST_P384,
                    /*custom_kid=*/"custom_kid",
                    /*id_requirement=*/absl::nullopt,
                    /*expected_kid=*/"custom_kid"},
           TestCase{JwtEcdsaParameters::KidStrategy::kIgnored,
                    JwtEcdsaParameters::Algorithm::kEs512,
                    subtle::EllipticCurveType::NIST_P521,
                    /*custom_kid=*/absl::nullopt,
                    /*id_requirement=*/absl::nullopt,
                    /*expected_kid=*/absl::nullopt}));

TEST_P(JwtEcdsaPrivateKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*parameters)
                                           .SetPublicPoint(public_point);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }
  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetKid(), Eq(test_case.expected_kid));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetPrivateKey(GetPartialKeyAccess()),
              Eq(private_key_value));
  EXPECT_THAT(private_key->GetPrivateKeyValue(GetPartialKeyAccess()),
              Eq(RestrictedBigInteger(
                  private_key_value.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetPrivateKey(GetPartialKeyAccess()).size(),
              Eq(parameters->GetPrivateKeyLength()));
}

TEST_P(JwtEcdsaPrivateKeyTest, CreateWithRestrictedBigIntegerSucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*parameters)
                                           .SetPublicPoint(public_point);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }
  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get());

  absl::StatusOr<RestrictedData> expected_private_key_data =
      private_key_value.EncodeWithFixedSize(parameters->GetPrivateKeyLength());

  ASSERT_THAT(expected_private_key_data, IsOk());
  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetKid(), Eq(test_case.expected_kid));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetPrivateKey(GetPartialKeyAccess()),
              Eq(*expected_private_key_data));
  EXPECT_THAT(private_key->GetPrivateKeyValue(GetPartialKeyAccess()),
              Eq(private_key_value));
}

TEST_P(JwtEcdsaPrivateKeyTest, CreatePrivateKeyAllowNonConstantTimeWorks) {
  TestCase test_case = GetParam();

  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*parameters)
                                           .SetPublicPoint(public_point);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }
  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key =
      JwtEcdsaPrivateKey::CreateAllowNonConstantTime(
          *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetKid(), Eq(test_case.expected_kid));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetPrivateKey(GetPartialKeyAccess()),
              Eq(private_key_value));
  EXPECT_THAT(private_key->GetPrivateKeyValue(GetPartialKeyAccess()),
              Eq(RestrictedBigInteger(
                  private_key_value.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetPrivateKey(GetPartialKeyAccess()).size(),
              Eq(parameters->GetPrivateKeyLength()));
}

TEST(JwtEcdsaPrivateKeyTest, CreatePrivateKeyWithOneTooManyBytes) {
  std::string public_x = HexDecodeOrDie(
      "bc95b9d6e70821a0bc477d7032085c780e2cae8fdf3d08508989f154b4c327d0");
  std::string public_y = HexDecodeOrDie(
      "6b7ae183d851aec7d1b81f3fb152aa5f661231953e0e4b7c99d14c3f671d3258");
  // Private key with 33 bytes (NIST P-256 takes 32 bytes).
  std::string private_key_bytes = HexDecodeOrDie(
      "ff5356ba39d3d19daab9f2146ae03f5c9b7f2f69a219356b2283977a5e55e5d0b8");
  ASSERT_THAT(private_key_bytes.length(), Eq(33));

  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  EcPoint public_point((BigInteger(public_x)), BigInteger(public_y));

  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*parameters)
                                           .SetPublicPoint(public_point);

  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      JwtEcdsaPrivateKey::Create(*public_key, private_key_value,
                                 GetPartialKeyAccess())
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          StrEq("Private key length 33 is different from expected length 32")));
  EXPECT_THAT(
      JwtEcdsaPrivateKey::CreateAllowNonConstantTime(
          *public_key, private_key_value, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument, StrEq("Integer too large")));
}

TEST(JwtEcdsaPrivateKeyTest, CreatePrivateKeyWithOneTooFewBytes) {
  std::string public_x = HexDecodeOrDie(
      "5e06e5dc416789b2377a305132455025354d27eec2420c30a0b1658503e14780");
  std::string public_y = HexDecodeOrDie(
      "f43e6af3ef0dabe891693cefc8bf3fe51733a02e19a6fa418a21fc2040ea1b92");
  // Private key with 33 bytes (NIST P-256 takes 32 bytes).
  std::string private_key_bytes = HexDecodeOrDie(
      "68e0e126325d313dd9cf888e1163c9844cc6f9d9e41ae075338d34e2878cb9");
  ASSERT_THAT(public_x.length(), Eq(32));
  ASSERT_THAT(public_y.length(), Eq(32));
  ASSERT_THAT(private_key_bytes.length(), Eq(31));

  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  EcPoint public_point((BigInteger(public_x)), BigInteger(public_y));

  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*parameters)
                                           .SetPublicPoint(public_point);

  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

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
  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key1 =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key1, IsOk());

  EcPoint public_point(BigInteger(ec_key1->pub_x), BigInteger(ec_key1->pub_y));

  absl::StatusOr<JwtEcdsaPublicKey> public_key1 =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  absl::StatusOr<internal::EcKey> ec_key2 =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key2, IsOk());

  RestrictedData private_key_bytes2 =
      RestrictedData(util::SecretDataAsStringView(ec_key2->priv),
                     InsecureSecretKeyAccess::Get());

  EXPECT_THAT(JwtEcdsaPrivateKey::Create(*public_key1, private_key_bytes2,
                                         GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid EC key pair")));
}

TEST_P(JwtEcdsaPrivateKeyTest, PrivateKeyEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*parameters)
                                           .SetPublicPoint(public_point);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }
  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<JwtEcdsaPrivateKey> other_private_key =
      JwtEcdsaPrivateKey::Create(*public_key, private_key_value,
                                 GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST(JwtEcdsaPrivateKeyTest, DifferentPublicKeyNotEqual) {
  absl::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<JwtEcdsaPublicKey> public_key1 =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  absl::StatusOr<JwtEcdsaPublicKey> public_key2 =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key1, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<JwtEcdsaPrivateKey> other_private_key =
      JwtEcdsaPrivateKey::Create(*public_key2, private_key_value,
                                 GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key != *other_private_key);
  EXPECT_TRUE(*other_private_key != *private_key);
  EXPECT_FALSE(*private_key == *other_private_key);
  EXPECT_FALSE(*other_private_key == *private_key);
}

TEST(JwtEcdsaPrivateKeyTest, DifferentKeyTypesNotEqual) {
  absl::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key != *public_key);
  EXPECT_TRUE(*public_key != *private_key);
  EXPECT_FALSE(*private_key == *public_key);
  EXPECT_FALSE(*public_key == *private_key);
}

TEST(JwtEcdsaPrivateKeyTest, Clone) {
  absl::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = private_key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*private_key));
}

TEST(JwtEcdsaPrivateKeyTest, CopyConstructor) {
  absl::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  JwtEcdsaPrivateKey copy(*private_key);

  EXPECT_THAT(copy, Eq(*private_key));
}

TEST(JwtEcdsaPrivateKeyTest, CopyAssignment) {
  absl::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<JwtEcdsaParameters> other_parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs384);
  ASSERT_THAT(other_parameters, IsOk());

  absl::StatusOr<internal::EcKey> other_ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P384);
  ASSERT_THAT(other_ec_key, IsOk());

  EcPoint other_public_point(BigInteger(other_ec_key->pub_x),
                             BigInteger(other_ec_key->pub_y));

  absl::StatusOr<JwtEcdsaPublicKey> other_public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*other_parameters)
          .SetPublicPoint(other_public_point)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  RestrictedData other_private_key_value =
      RestrictedData(util::SecretDataAsStringView(other_ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtEcdsaPrivateKey> copy = JwtEcdsaPrivateKey::Create(
      *other_public_key, other_private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *private_key;

  EXPECT_THAT(*copy, Eq(*private_key));
}

TEST(JwtEcdsaPrivateKeyTest, MoveConstructor) {
  absl::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  JwtEcdsaPrivateKey expected = *private_key;
  JwtEcdsaPrivateKey moved(std::move(*private_key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(JwtEcdsaPrivateKeyTest, MoveAssignment) {
  absl::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<JwtEcdsaParameters> other_parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs384);
  ASSERT_THAT(other_parameters, IsOk());

  absl::StatusOr<internal::EcKey> other_ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P384);
  ASSERT_THAT(other_ec_key, IsOk());

  EcPoint other_public_point(BigInteger(other_ec_key->pub_x),
                             BigInteger(other_ec_key->pub_y));

  absl::StatusOr<JwtEcdsaPublicKey> other_public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*other_parameters)
          .SetPublicPoint(other_public_point)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  RestrictedData other_private_key_value =
      RestrictedData(util::SecretDataAsStringView(other_ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtEcdsaPrivateKey> moved = JwtEcdsaPrivateKey::Create(
      *other_public_key, other_private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(moved, IsOk());

  JwtEcdsaPrivateKey expected = *private_key;
  *moved = std::move(*private_key);

  EXPECT_THAT(*moved, Eq(expected));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
