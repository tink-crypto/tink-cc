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
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
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

  util::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
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
  util::StatusOr<JwtEcdsaPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get());

  util::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetKid(), Eq(test_case.expected_kid));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetPrivateKeyValue(GetPartialKeyAccess()),
              Eq(private_key_value));
}

TEST(JwtEcdsaPrivateKeyTest, CreateMismatchedKeyPairFails) {
  util::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<internal::EcKey> ec_key1 =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key1, IsOk());

  EcPoint public_point(BigInteger(ec_key1->pub_x), BigInteger(ec_key1->pub_y));

  util::StatusOr<JwtEcdsaPublicKey> public_key1 =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  util::StatusOr<internal::EcKey> ec_key2 =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key2, IsOk());

  RestrictedBigInteger private_key_bytes2 =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key2->priv),
                           InsecureSecretKeyAccess::Get());

  EXPECT_THAT(JwtEcdsaPrivateKey::Create(*public_key1, private_key_bytes2,
                                         GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid EC key pair")));
}

TEST_P(JwtEcdsaPrivateKeyTest, PrivateKeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
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
  util::StatusOr<JwtEcdsaPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get());

  util::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<JwtEcdsaPrivateKey> other_private_key =
      JwtEcdsaPrivateKey::Create(*public_key, private_key_value,
                                 GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST(JwtEcdsaPrivateKeyTest, DifferentPublicKeyNotEqual) {
  util::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  util::StatusOr<JwtEcdsaPublicKey> public_key1 =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  util::StatusOr<JwtEcdsaPublicKey> public_key2 =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get());

  util::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key1, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<JwtEcdsaPrivateKey> other_private_key =
      JwtEcdsaPrivateKey::Create(*public_key2, private_key_value,
                                 GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key != *other_private_key);
  EXPECT_TRUE(*other_private_key != *private_key);
  EXPECT_FALSE(*private_key == *other_private_key);
  EXPECT_FALSE(*other_private_key == *private_key);
}

TEST(JwtEcdsaPrivateKeyTest, DifferentKeyTypesNotEqual) {
  util::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  util::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get());

  util::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key != *public_key);
  EXPECT_TRUE(*public_key != *private_key);
  EXPECT_FALSE(*private_key == *public_key);
  EXPECT_FALSE(*public_key == *private_key);
}

TEST(JwtEcdsaPrivateKeyTest, Clone) {
  util::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  util::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get());

  util::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = private_key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*private_key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
