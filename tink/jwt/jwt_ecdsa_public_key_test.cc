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

#include "tink/jwt/jwt_ecdsa_public_key.h"

#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/internal/ec_util.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Lt;
using ::testing::SizeIs;
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

using JwtEcdsaPublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    JwtEcdsaPublicKeyTestSuite, JwtEcdsaPublicKeyTest,
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

TEST_P(JwtEcdsaPublicKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  util::StatusOr<JwtEcdsaParameters> params =
      JwtEcdsaParameters::Create(test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder().SetParameters(*params).SetPublicPoint(
          public_point);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }
  util::StatusOr<JwtEcdsaPublicKey> key = builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*params));
  EXPECT_THAT(key->GetPublicPoint(GetPartialKeyAccess()), Eq(public_point));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetKid(), Eq(test_case.expected_kid));
}

TEST(JwtEcdsaPublicKeyTest, CreateKeyWithInvalidPublicPointFails) {
  util::StatusOr<JwtEcdsaParameters> params =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(params, IsOk());

  // Copied from "public point not on curve" Wycheproof test case in
  //
  // https://github.com/google/wycheproof/blob/master/testvectors/ecdh_secp256k1_test.json.
  std::string invalid_point = absl::HexStringToBytes(
      "3056301006072a8648ce3d020106052b8104000a0342000449c248edc659e18482b71057"
      "48a4b95d3a46952a5ba72da0d702dc97a64e99799d8cff7a5c4b925e4360ece25ccf307d"
      "7a9a7063286bbd16ef64c65f546757e4");

  util::StatusOr<int32_t> point_size =
      internal::EcPointEncodingSizeInBytes(subtle::EllipticCurveType::NIST_P256,
                                           subtle::EcPointFormat::UNCOMPRESSED);
  ASSERT_THAT(point_size, IsOk());
  ASSERT_THAT(*point_size, Lt(invalid_point.size()));

  std::string public_key_bytes =
      invalid_point.substr(invalid_point.size() - *point_size, *point_size);
  // Uncompressed point format starts with a 0x04-byte.
  ASSERT_THAT(public_key_bytes, SizeIs(65));
  ASSERT_THAT(public_key_bytes[0], Eq(0x04));

  BigInteger x(public_key_bytes.substr(1, 32));
  BigInteger y(public_key_bytes.substr(33, 32));
  EcPoint public_point(x, y);

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder().SetParameters(*params).SetPublicPoint(
          public_point);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(JwtEcdsaPublicKeyTest, CreateBase64EncodedKidWithoutIdRequirementFails) {
  util::StatusOr<JwtEcdsaParameters> params = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder().SetParameters(*params).SetPublicPoint(
          public_point);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key without ID requirement "
                                 "with parameters with ID requirement")));
}

TEST(JwtEcdsaPublicKeyTest, CreateBase64EncodedKidWithCustomKidFails) {
  util::StatusOr<JwtEcdsaParameters> params = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*params)
                                           .SetPublicPoint(public_point)
                                           .SetIdRequirement(123)
                                           .SetCustomKid("custom_kid");

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Custom kid must not be set for "
                                 "KidStrategy::kBase64EncodedKeyId")));
}

TEST(JwtEcdsaPublicKeyTest, CreateCustomKidWithIdRequirementFails) {
  util::StatusOr<JwtEcdsaParameters> params =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kCustom,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*params)
                                           .SetPublicPoint(public_point)
                                           .SetCustomKid("custom_kid")
                                           .SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement with "
                                 "parameters without ID requirement")));
}

TEST(JwtEcdsaPublicKeyTest, CreateCustomKidWithoutCustomKidFails) {
  util::StatusOr<JwtEcdsaParameters> params =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kCustom,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder().SetParameters(*params).SetPublicPoint(
          public_point);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Custom kid must be set")));
}

TEST(JwtEcdsaPublicKeyTest, CreateIgnoredKidWithIdRequirementFails) {
  util::StatusOr<JwtEcdsaParameters> params =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*params)
                                           .SetPublicPoint(public_point)
                                           .SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement with "
                                 "parameters without ID requirement")));
}

TEST(JwtEcdsaPublicKeyTest, CreateIgnoredKidWithCustomKidFails) {
  util::StatusOr<JwtEcdsaParameters> params =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*params)
                                           .SetPublicPoint(public_point)
                                           .SetCustomKid("custom_kid");

  EXPECT_THAT(
      builder.Build(GetPartialKeyAccess()).status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Custom kid must not be set for KidStrategy::kIgnored")));
}

TEST(JwtEcdsaPublicKeyTest, CreateWithMissingParametersFails) {
  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder().SetPublicPoint(public_point);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("JWT ECDSA parameters must be specified")));
}

TEST(JwtEcdsaPublicKeyTest, CreateWithMissingPublicPointFails) {
  util::StatusOr<JwtEcdsaParameters> params =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(params, IsOk());

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder().SetParameters(*params);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("JWT ECDSA public point must be specified")));
}

TEST_P(JwtEcdsaPublicKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<JwtEcdsaParameters> params =
      JwtEcdsaParameters::Create(test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder().SetParameters(*params).SetPublicPoint(
          public_point);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }
  util::StatusOr<JwtEcdsaPublicKey> key = builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  JwtEcdsaPublicKey::Builder other_builder =
      JwtEcdsaPublicKey::Builder().SetParameters(*params).SetPublicPoint(
          public_point);
  if (test_case.id_requirement.has_value()) {
    other_builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    other_builder.SetCustomKid(*test_case.custom_kid);
  }
  util::StatusOr<JwtEcdsaPublicKey> other_key =
      other_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(JwtEcdsaPublicKeyTest, DifferentPublicPointNotEqual) {
  util::StatusOr<JwtEcdsaParameters> params = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  util::StatusOr<internal::EcKey> other_ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(other_ec_key, IsOk());

  EcPoint other_public_point(BigInteger(other_ec_key->pub_x),
                             BigInteger(other_ec_key->pub_y));

  util::StatusOr<JwtEcdsaPublicKey> key = JwtEcdsaPublicKey::Builder()
                                              .SetParameters(*params)
                                              .SetPublicPoint(public_point)
                                              .SetIdRequirement(123)
                                              .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<JwtEcdsaPublicKey> other_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicPoint(other_public_point)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(JwtEcdsaPublicKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<JwtEcdsaParameters> params = JwtEcdsaParameters::Create(
      JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  util::StatusOr<JwtEcdsaPublicKey> key = JwtEcdsaPublicKey::Builder()
                                              .SetParameters(*params)
                                              .SetPublicPoint(public_point)
                                              .SetIdRequirement(123)
                                              .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<JwtEcdsaPublicKey> other_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicPoint(public_point)
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(JwtEcdsaPublicKeyTest, DifferentCustomKidNotEqual) {
  util::StatusOr<JwtEcdsaParameters> params =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kCustom,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(params, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  util::StatusOr<JwtEcdsaPublicKey> key = JwtEcdsaPublicKey::Builder()
                                              .SetParameters(*params)
                                              .SetPublicPoint(public_point)
                                              .SetCustomKid("custom_kid")
                                              .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<JwtEcdsaPublicKey> other_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*params)
          .SetPublicPoint(public_point)
          .SetCustomKid("other_custom_kid")
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
