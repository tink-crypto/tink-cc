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

#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/string_view.h"
#include "tink/big_integer.h"
#include "tink/jwt/internal/testing/jwt_rsa_ssa_test_vectors.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  JwtRsaSsaPssParameters::Algorithm algorithm;
  JwtRsaSsaPssParameters::KidStrategy kid_strategy;
  std::optional<int> id_requirement;
  std::optional<std::string> custom_kid;
  std::optional<std::string> expected_kid;
};

// Returns static F4 public exponent (65537).
const BigInteger& GetF4() {
  static const absl::NoDestructor<BigInteger> f4(std::string("\x1\0\x1", 3));
  return *f4;
}

constexpr int kModulusSizeInBits = 2048;

struct KeyParams {
  JwtRsaSsaPssParameters::Algorithm algorithm;
  JwtRsaSsaPssParameters::KidStrategy kid_strategy;
  std::optional<int> id_requirement;
  std::optional<std::string> custom_kid;
  std::string modulus;

  template <typename H>
  friend H AbslHashValue(H h, const KeyParams& params) {
    return H::combine(std::move(h), params.algorithm, params.kid_strategy,
                      params.id_requirement, params.custom_kid, params.modulus);
  }

  bool operator==(const KeyParams& other) const {
    return algorithm == other.algorithm && kid_strategy == other.kid_strategy &&
           id_requirement == other.id_requirement &&
           custom_kid == other.custom_kid && modulus == other.modulus;
  }
};

using PublicKeyMap = absl::flat_hash_map<KeyParams, JwtRsaSsaPssPublicKey>;

JwtRsaSsaPssPublicKey CreateValidPublicKey(
    JwtRsaSsaPssParameters::Algorithm algorithm,
    JwtRsaSsaPssParameters::KidStrategy kid_strategy,
    std::optional<int> id_requirement, std::optional<std::string> custom_kid,
    absl::string_view modulus) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(GetF4())
          .SetAlgorithm(algorithm)
          .SetKidStrategy(kid_strategy)
          .Build();
  ABSL_CHECK_OK(parameters.status()) << "Failed to create parameters.";

  JwtRsaSsaPssPublicKey::Builder builder = JwtRsaSsaPssPublicKey::Builder()
                                               .SetParameters(*parameters)
                                               .SetModulus(BigInteger(modulus));
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(*id_requirement);
  }
  if (custom_kid.has_value()) {
    builder.SetCustomKid(*custom_kid);
  }

  absl::StatusOr<JwtRsaSsaPssPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status()) << "Failed to create public key.";
  return *public_key;
}

// Returns static valid public key.
const JwtRsaSsaPssPublicKey& GetValidPublicKey(
    JwtRsaSsaPssParameters::Algorithm algorithm =
        JwtRsaSsaPssParameters::Algorithm::kPs256,
    JwtRsaSsaPssParameters::KidStrategy kid_strategy =
        JwtRsaSsaPssParameters::KidStrategy::kIgnored,
    std::optional<int> id_requirement = std::nullopt,
    std::optional<std::string> custom_kid = std::nullopt,
    absl::string_view modulus = jwt_internal::GetRsa2048BitVector1().n) {
  static const absl::NoDestructor<PublicKeyMap> keys([]() {
    PublicKeyMap map;
    auto insert_key = [&](JwtRsaSsaPssParameters::Algorithm alg,
                          JwtRsaSsaPssParameters::KidStrategy kid_strat,
                          std::optional<int> id_req,
                          std::optional<std::string> custom_k,
                          absl::string_view mod) {
      map.emplace(KeyParams{alg, kid_strat, id_req, custom_k, std::string(mod)},
                  CreateValidPublicKey(alg, kid_strat, id_req, custom_k, mod));
    };
    // Suite test cases.
    insert_key(JwtRsaSsaPssParameters::Algorithm::kPs256,
               JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId,
               0x1ac6a944, std::nullopt,
               jwt_internal::GetRsa2048BitVector1().n);
    insert_key(JwtRsaSsaPssParameters::Algorithm::kPs384,
               JwtRsaSsaPssParameters::KidStrategy::kCustom, std::nullopt,
               "custom_kid", jwt_internal::GetRsa2048BitVector1().n);
    insert_key(JwtRsaSsaPssParameters::Algorithm::kPs512,
               JwtRsaSsaPssParameters::KidStrategy::kIgnored, std::nullopt,
               std::nullopt, jwt_internal::GetRsa2048BitVector1().n);
    // DifferentIdRequirementNotEqual.
    insert_key(JwtRsaSsaPssParameters::Algorithm::kPs256,
               JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId, 123,
               std::nullopt, jwt_internal::GetRsa2048BitVector1().n);
    insert_key(JwtRsaSsaPssParameters::Algorithm::kPs256,
               JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId, 456,
               std::nullopt, jwt_internal::GetRsa2048BitVector1().n);
    // DifferentModulusNotEqual.
    insert_key(JwtRsaSsaPssParameters::Algorithm::kPs256,
               JwtRsaSsaPssParameters::KidStrategy::kIgnored, std::nullopt,
               std::nullopt, jwt_internal::GetRsa2048BitVector1().n);
    insert_key(JwtRsaSsaPssParameters::Algorithm::kPs256,
               JwtRsaSsaPssParameters::KidStrategy::kIgnored, std::nullopt,
               std::nullopt, jwt_internal::GetRsa2048BitVector2().n);
    // DifferentCustomKidNotEqual and Clone.
    insert_key(JwtRsaSsaPssParameters::Algorithm::kPs256,
               JwtRsaSsaPssParameters::KidStrategy::kCustom, std::nullopt,
               "custom_kid", jwt_internal::GetRsa2048BitVector1().n);
    insert_key(JwtRsaSsaPssParameters::Algorithm::kPs256,
               JwtRsaSsaPssParameters::KidStrategy::kCustom, std::nullopt,
               "other_custom_kid", jwt_internal::GetRsa2048BitVector1().n);
    return map;
  }());
  auto it = keys->find(KeyParams{algorithm, kid_strategy, id_requirement,
                                 custom_kid, std::string(modulus)});
  ABSL_CHECK(it != keys->end()) << "No static public key found.";
  return it->second;
}

const JwtRsaSsaPssPublicKey& GetValidPublicKey(const TestCase& test_case) {
  return GetValidPublicKey(test_case.algorithm, test_case.kid_strategy,
                           test_case.id_requirement, test_case.custom_kid);
}

using JwtRsaSsaPssPublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    JwtRsaSsaPssPublicKeyTestSuite, JwtRsaSsaPssPublicKeyTest,
    Values(TestCase{JwtRsaSsaPssParameters::Algorithm::kPs256,
                    JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId,
                    /*id_requirement=*/0x1ac6a944,
                    /*custom_kid=*/std::nullopt, /*expected_kid=*/"GsapRA"},
           TestCase{JwtRsaSsaPssParameters::Algorithm::kPs384,
                    JwtRsaSsaPssParameters::KidStrategy::kCustom,
                    /*id_requirement=*/std::nullopt,
                    /*custom_kid=*/"custom_kid", /*expected_kid=*/"custom_kid"},
           TestCase{JwtRsaSsaPssParameters::Algorithm::kPs512,
                    JwtRsaSsaPssParameters::KidStrategy::kIgnored,
                    /*id_requirement=*/std::nullopt,
                    /*custom_kid=*/std::nullopt,
                    /*expected_kid=*/std::nullopt}));

TEST_P(JwtRsaSsaPssPublicKeyTest, BuildWorks) {
  TestCase test_case = GetParam();

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetAlgorithm(test_case.algorithm)
          .SetKidStrategy(test_case.kid_strategy)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(jwt_internal::GetRsa2048BitVector1().n);
  JwtRsaSsaPssPublicKey::Builder builder = JwtRsaSsaPssPublicKey::Builder()
                                               .SetParameters(*parameters)
                                               .SetModulus(modulus);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }

  absl::StatusOr<JwtRsaSsaPssPublicKey> key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetModulus(GetPartialKeyAccess()), Eq(modulus));
  EXPECT_THAT(key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(key->GetKid(), Eq(test_case.expected_kid));
}

TEST(JwtRsaSsaPssPublicKeyTest, CustomKidPreservesStringViewBounds) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kCustom)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string backing = "custom_kid|secret";
  absl::string_view custom_kid(backing.data(), /*len=*/10);
  absl::StatusOr<JwtRsaSsaPssPublicKey> key =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(jwt_internal::GetRsa2048BitVector1().n))
          .SetCustomKid(custom_kid)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  ASSERT_TRUE(key->GetKid().has_value());
  EXPECT_EQ(*key->GetKid(), "custom_kid");
}

TEST(JwtRsaSsaPssPublicKeyTest, BuildWithoutModulusFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .Build(GetPartialKeyAccess());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                     HasSubstr("modulus must be specified")));
}

TEST(JwtRsaSsaPssPublicKeyTest, BuildWithNonMatchingModulusSizeFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(GetF4())
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(jwt_internal::GetRsa2048BitVector1().n);
  absl::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .Build(GetPartialKeyAccess());
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid modulus length (expected 3072, got 2048)")));
}

TEST(JwtEcdsaPublicKeyTest, BuildBase64EncodedKidWithoutIdRequirementFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(jwt_internal::GetRsa2048BitVector1().n);
  absl::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .Build(GetPartialKeyAccess());

  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key without ID requirement "
                                 "with parameters with ID requirement")));
}

TEST(JwtEcdsaPublicKeyTest, BuildBase64EncodedKidWithCustomKidFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(jwt_internal::GetRsa2048BitVector1().n);
  absl::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .SetIdRequirement(123)
                                                  .SetCustomKid("custom_kid")
                                                  .Build(GetPartialKeyAccess());

  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Custom kid must not be set for "
                                 "KidStrategy::kBase64EncodedKeyId")));
}

TEST(JwtEcdsaPublicKeyTest, BuildCustomKidWithIdRequirementFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kCustom)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(jwt_internal::GetRsa2048BitVector1().n);
  absl::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .SetIdRequirement(123)
                                                  .SetCustomKid("custom_kid")
                                                  .Build(GetPartialKeyAccess());

  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement with "
                                 "parameters without ID requirement")));
}

TEST(JwtEcdsaPublicKeyTest, BuildCustomKidWithoutCustomKidFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kCustom)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(jwt_internal::GetRsa2048BitVector1().n);
  absl::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .Build(GetPartialKeyAccess());

  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Custom kid must be set for KidStrategy::kCustom")));
}

TEST(JwtEcdsaPublicKeyTest, BuildIgnoredKidWithIdRequirementFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(jwt_internal::GetRsa2048BitVector1().n);
  absl::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .SetIdRequirement(123)
                                                  .Build(GetPartialKeyAccess());

  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement with "
                                 "parameters without ID requirement")));
}

TEST(JwtEcdsaPublicKeyTest, BuildIgnoredKidWithCustomKidFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(jwt_internal::GetRsa2048BitVector1().n);
  absl::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .SetModulus(modulus)
                                                  .SetCustomKid("custom_kid")
                                                  .Build(GetPartialKeyAccess());

  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Custom kid must not be set for KidStrategy::kIgnored")));
}

TEST(JwtEcdsaPublicKeyTest, BuildWithMissingParametersFails) {
  BigInteger modulus(jwt_internal::GetRsa2048BitVector1().n);
  absl::StatusOr<JwtRsaSsaPssPublicKey> key =
      JwtRsaSsaPssPublicKey::Builder().SetModulus(modulus).Build(
          GetPartialKeyAccess());

  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("parameters must be specified")));
}

TEST(JwtEcdsaPublicKeyTest, BuildWithMissingModulusFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPssPublicKey> key = JwtRsaSsaPssPublicKey::Builder()
                                                  .SetParameters(*parameters)
                                                  .Build(GetPartialKeyAccess());

  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                     HasSubstr("modulus must be specified")));
}

TEST_P(JwtRsaSsaPssPublicKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  const JwtRsaSsaPssPublicKey& key = GetValidPublicKey(test_case);
  JwtRsaSsaPssPublicKey other_key = key;

  EXPECT_TRUE(key == other_key);
  EXPECT_TRUE(other_key == key);
  EXPECT_FALSE(key != other_key);
  EXPECT_FALSE(other_key != key);
}

TEST(JwtRsaSsaPssPublicKeyTest, DifferentIdRequirementNotEqual) {
  const JwtRsaSsaPssPublicKey& key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId,
      /*id_requirement=*/123, /*custom_kid=*/std::nullopt);
  const JwtRsaSsaPssPublicKey& other_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId,
      /*id_requirement=*/456, /*custom_kid=*/std::nullopt);

  EXPECT_TRUE(key != other_key);
  EXPECT_TRUE(other_key != key);
  EXPECT_FALSE(key == other_key);
  EXPECT_FALSE(other_key == key);
}

TEST(JwtRsaSsaPssPublicKeyTest, DifferentModulusNotEqual) {
  const JwtRsaSsaPssPublicKey& key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /*id_requirement=*/std::nullopt, /*custom_kid=*/std::nullopt,
      jwt_internal::GetRsa2048BitVector1().n);
  const JwtRsaSsaPssPublicKey& other_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /*id_requirement=*/std::nullopt, /*custom_kid=*/std::nullopt,
      jwt_internal::GetRsa2048BitVector2().n);

  EXPECT_TRUE(key != other_key);
  EXPECT_TRUE(other_key != key);
  EXPECT_FALSE(key == other_key);
  EXPECT_FALSE(other_key == key);
}

TEST(JwtRsaSsaPssPublicKeyTest, DifferentCustomKidNotEqual) {
  const JwtRsaSsaPssPublicKey& key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kCustom,
      /*id_requirement=*/std::nullopt, /*custom_kid=*/"custom_kid");
  const JwtRsaSsaPssPublicKey& other_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kCustom,
      /*id_requirement=*/std::nullopt, /*custom_kid=*/"other_custom_kid");

  EXPECT_TRUE(key != other_key);
  EXPECT_TRUE(other_key != key);
  EXPECT_FALSE(key == other_key);
  EXPECT_FALSE(other_key == key);
}

TEST(JwtRsaSsaPssPublicKeyTest, Clone) {
  const JwtRsaSsaPssPublicKey& key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kCustom,
      /*id_requirement=*/std::nullopt, /*custom_kid=*/"custom_kid");

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
