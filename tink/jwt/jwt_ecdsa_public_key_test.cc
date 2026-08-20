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
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/internal/ec_util.h"
#include "tink/jwt/internal/testing/jwt_ecdsa_test_vectors.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Lt;
using ::testing::SizeIs;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using JwtEcdsaPublicKeyTest = TestWithParam<jwt_internal::JwtEcdsaTestVector>;

INSTANTIATE_TEST_SUITE_P(JwtEcdsaPublicKeyTestSuite, JwtEcdsaPublicKeyTest,
                         ValuesIn(jwt_internal::CreateJwtEcdsaTestVectors()));

TEST_P(JwtEcdsaPublicKeyTest, CreateSucceeds) {
  const jwt_internal::JwtEcdsaTestVector& test_vector = GetParam();
  const JwtEcdsaPublicKey& key = test_vector.key.GetPublicKey();

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(key.GetParameters())
          .SetPublicPoint(key.GetPublicPoint(GetPartialKeyAccess()));
  if (key.GetIdRequirement().has_value()) {
    builder.SetIdRequirement(*key.GetIdRequirement());
  }
  if (key.GetParameters().GetKidStrategy() ==
      JwtEcdsaParameters::KidStrategy::kCustom) {
    builder.SetCustomKid(*key.GetKid());
  }
  absl::StatusOr<JwtEcdsaPublicKey> created_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(created_key, IsOk());

  EXPECT_THAT(created_key->GetParameters(), Eq(key.GetParameters()));
  EXPECT_THAT(created_key->GetPublicPoint(GetPartialKeyAccess()),
              Eq(key.GetPublicPoint(GetPartialKeyAccess())));
  EXPECT_THAT(created_key->GetIdRequirement(), Eq(key.GetIdRequirement()));
  EXPECT_THAT(created_key->GetKid(), Eq(key.GetKid()));
}

TEST(JwtEcdsaPublicKeyTest, CustomKidPreservesStringViewBounds) {
  const JwtEcdsaPublicKey& valid_key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P384)
          .key.GetPublicKey();

  std::string backing = "custom_kid|secret";
  absl::string_view custom_kid(backing.data(), /*len=*/10);
  absl::StatusOr<JwtEcdsaPublicKey> key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetPublicPoint(valid_key.GetPublicPoint(GetPartialKeyAccess()))
          .SetCustomKid(custom_kid)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  ASSERT_TRUE(key->GetKid().has_value());
  EXPECT_EQ(*key->GetKid(), "custom_kid");
}

TEST(JwtEcdsaPublicKeyTest, CreateKeyWithInvalidPublicPointFails) {
  const JwtEcdsaPublicKey& valid_key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key.GetPublicKey();

  // Copied from "public point not on curve" Wycheproof test case in
  //
  // https://github.com/google/wycheproof/blob/master/testvectors/ecdh_secp256k1_test.json.
  std::string invalid_point = test::HexDecodeOrDie(
      "3056301006072a8648ce3d020106052b8104000a0342000449c248edc659e18482b71057"
      "48a4b95d3a46952a5ba72da0d702dc97a64e99799d8cff7a5c4b925e4360ece25ccf307d"
      "7a9a7063286bbd16ef64c65f546757e4");

  absl::StatusOr<int32_t> point_size =
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
      JwtEcdsaPublicKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetPublicPoint(public_point);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(JwtEcdsaPublicKeyTest, CreateBase64EncodedKidWithoutIdRequirementFails) {
  const JwtEcdsaPublicKey& valid_key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key.GetPublicKey();

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetPublicPoint(valid_key.GetPublicPoint(GetPartialKeyAccess()));

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key without ID requirement "
                                 "with parameters with ID requirement")));
}

TEST(JwtEcdsaPublicKeyTest, CreateBase64EncodedKidWithCustomKidFails) {
  const JwtEcdsaPublicKey& valid_key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key.GetPublicKey();

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetPublicPoint(valid_key.GetPublicPoint(GetPartialKeyAccess()))
          .SetIdRequirement(123)
          .SetCustomKid("custom_kid");

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Custom kid must not be set for "
                                 "KidStrategy::kBase64EncodedKeyId")));
}

TEST(JwtEcdsaPublicKeyTest, CreateCustomKidWithIdRequirementFails) {
  const JwtEcdsaPublicKey& valid_key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P384)
          .key.GetPublicKey();

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetPublicPoint(valid_key.GetPublicPoint(GetPartialKeyAccess()))
          .SetCustomKid("custom_kid")
          .SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement with "
                                 "parameters without ID requirement")));
}

TEST(JwtEcdsaPublicKeyTest, CreateCustomKidWithoutCustomKidFails) {
  const JwtEcdsaPublicKey& valid_key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P384)
          .key.GetPublicKey();

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetPublicPoint(valid_key.GetPublicPoint(GetPartialKeyAccess()));

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Custom kid must be set")));
}

TEST(JwtEcdsaPublicKeyTest, CreateIgnoredKidWithIdRequirementFails) {
  const JwtEcdsaPublicKey& valid_key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P521)
          .key.GetPublicKey();

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetPublicPoint(valid_key.GetPublicPoint(GetPartialKeyAccess()))
          .SetIdRequirement(123);

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement with "
                                 "parameters without ID requirement")));
}

TEST(JwtEcdsaPublicKeyTest, CreateIgnoredKidWithCustomKidFails) {
  const JwtEcdsaPublicKey& valid_key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P521)
          .key.GetPublicKey();

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(valid_key.GetParameters())
          .SetPublicPoint(valid_key.GetPublicPoint(GetPartialKeyAccess()))
          .SetCustomKid("custom_kid");

  EXPECT_THAT(
      builder.Build(GetPartialKeyAccess()).status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Custom kid must not be set for KidStrategy::kIgnored")));
}

TEST(JwtEcdsaPublicKeyTest, CreateWithMissingParametersFails) {
  const JwtEcdsaPublicKey& valid_key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key.GetPublicKey();

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder().SetPublicPoint(
          valid_key.GetPublicPoint(GetPartialKeyAccess()));

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("JWT ECDSA parameters must be specified")));
}

TEST(JwtEcdsaPublicKeyTest, CreateWithMissingPublicPointFails) {
  const JwtEcdsaPublicKey& valid_key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key.GetPublicKey();

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder().SetParameters(valid_key.GetParameters());

  EXPECT_THAT(builder.Build(GetPartialKeyAccess()).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("JWT ECDSA public point must be specified")));
}

TEST_P(JwtEcdsaPublicKeyTest, KeyEquals) {
  const jwt_internal::JwtEcdsaTestVector& test_vector = GetParam();
  const JwtEcdsaPublicKey& key = test_vector.key.GetPublicKey();

  JwtEcdsaPublicKey::Builder builder =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(key.GetParameters())
          .SetPublicPoint(key.GetPublicPoint(GetPartialKeyAccess()));
  if (key.GetIdRequirement().has_value()) {
    builder.SetIdRequirement(*key.GetIdRequirement());
  }
  if (key.GetParameters().GetKidStrategy() ==
      JwtEcdsaParameters::KidStrategy::kCustom) {
    builder.SetCustomKid(*key.GetKid());
  }
  absl::StatusOr<JwtEcdsaPublicKey> other_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(key == *other_key);
  EXPECT_TRUE(*other_key == key);
  EXPECT_FALSE(key != *other_key);
  EXPECT_FALSE(*other_key != key);
}

TEST(JwtEcdsaPublicKeyTest, DifferentPublicPointNotEqual) {
  const JwtEcdsaPublicKey& key1 =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key.GetPublicKey();
  const JwtEcdsaPublicKey& wycheproof_key =
      jwt_internal::GetJwtEcdsaWycheproofTestVector().key.GetPublicKey();

  absl::StatusOr<JwtEcdsaPublicKey> other_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(key1.GetParameters())
          .SetPublicPoint(wycheproof_key.GetPublicPoint(GetPartialKeyAccess()))
          .SetIdRequirement(*key1.GetIdRequirement())
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(key1 != *other_key);
  EXPECT_TRUE(*other_key != key1);
  EXPECT_FALSE(key1 == *other_key);
  EXPECT_FALSE(*other_key == key1);
}

TEST(JwtEcdsaPublicKeyTest, DifferentIdRequirementNotEqual) {
  const JwtEcdsaPublicKey& key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key.GetPublicKey();

  absl::StatusOr<JwtEcdsaPublicKey> other_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(key.GetParameters())
          .SetPublicPoint(key.GetPublicPoint(GetPartialKeyAccess()))
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(key != *other_key);
  EXPECT_TRUE(*other_key != key);
  EXPECT_FALSE(key == *other_key);
  EXPECT_FALSE(*other_key == key);
}

TEST(JwtEcdsaPublicKeyTest, DifferentCustomKidNotEqual) {
  const JwtEcdsaPublicKey& key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P384)
          .key.GetPublicKey();

  absl::StatusOr<JwtEcdsaPublicKey> other_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(key.GetParameters())
          .SetPublicPoint(key.GetPublicPoint(GetPartialKeyAccess()))
          .SetCustomKid("other_custom_kid")
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(key != *other_key);
  EXPECT_TRUE(*other_key != key);
  EXPECT_FALSE(key == *other_key);
  EXPECT_FALSE(*other_key == key);
}

TEST(JwtEcdsaPublicKeyTest, Clone) {
  const JwtEcdsaPublicKey& key =
      jwt_internal::GetJwtEcdsaTestVector(subtle::EllipticCurveType::NIST_P256)
          .key.GetPublicKey();

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
