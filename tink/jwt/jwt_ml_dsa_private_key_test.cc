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

#include "tink/jwt/jwt_ml_dsa_private_key.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"  // IWYU pragma: keep
#include "tink/jwt/internal/testing/jwt_ml_dsa_test_vectors.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/jwt/jwt_ml_dsa_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

#ifdef TINK_USE_ONLY_FIPS
using JwtMlDsaPrivateKeyTest = TestWithParam<JwtMlDsaParameters::Algorithm>;

INSTANTIATE_TEST_SUITE_P(JwtMlDsaPrivateKeyTestSuite, JwtMlDsaPrivateKeyTest,
                         Values(JwtMlDsaParameters::Algorithm::kMlDsa44,
                                JwtMlDsaParameters::Algorithm::kMlDsa65,
                                JwtMlDsaParameters::Algorithm::kMlDsa87));

TEST_P(JwtMlDsaPrivateKeyTest, CreateFipsFails) {
  JwtMlDsaParameters::Algorithm algorithm = GetParam();
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kIgnored, algorithm);
  ASSERT_THAT(parameters, IsOk());

  const jwt_internal::JwtMlDsaTestVector& test_vector =
      jwt_internal::GetJwtMlDsaTestVector(algorithm);
  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicKeyBytes(test_vector.public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_seed_bytes = RestrictedData(
      test_vector.private_seed_bytes, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      JwtMlDsaPrivateKey::Create(*public_key, private_seed_bytes,
                                 GetPartialKeyAccess())
          .status(),
      StatusIs(
          absl::StatusCode::kUnimplemented,
          HasSubstr("ML-DSA is only supported in non-FIPS BoringSSL builds.")));
}
#else
struct TestCase {
  JwtMlDsaParameters::KidStrategy kid_strategy;
  JwtMlDsaParameters::Algorithm algorithm;
  absl::optional<std::string> custom_kid;
  absl::optional<int> id_requirement;
  absl::optional<std::string> expected_kid;
  std::string public_key_bytes;
  std::string private_key_bytes;
};

using JwtMlDsaPrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    JwtMlDsaPrivateKeyTestSuite, JwtMlDsaPrivateKeyTest,
    Values(
        TestCase{JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
                 JwtMlDsaParameters::Algorithm::kMlDsa44,
                 /*custom_kid=*/std::nullopt, /*id_requirement=*/123,
                 /*expected_kid=*/"AAAAew",
                 /*public_key_bytes=*/
                 jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes,
                 /*private_key_bytes=*/
                 jwt_internal::CreateJwtMlDsa44TestVector().private_seed_bytes},
        TestCase{JwtMlDsaParameters::KidStrategy::kCustom,
                 JwtMlDsaParameters::Algorithm::kMlDsa65,
                 /*custom_kid=*/"custom_kid",
                 /*id_requirement=*/std::nullopt,
                 /*expected_kid=*/"custom_kid",
                 /*public_key_bytes=*/
                 jwt_internal::CreateJwtMlDsa65TestVector().public_key_bytes,
                 /*private_key_bytes=*/
                 jwt_internal::CreateJwtMlDsa65TestVector().private_seed_bytes},
        TestCase{
            JwtMlDsaParameters::KidStrategy::kIgnored,
            JwtMlDsaParameters::Algorithm::kMlDsa87,
            /*custom_kid=*/std::nullopt,
            /*id_requirement=*/std::nullopt,
            /*expected_kid=*/std::nullopt,
            /*public_key_bytes=*/
            jwt_internal::CreateJwtMlDsa87TestVector().public_key_bytes,
            /*private_key_bytes=*/
            jwt_internal::CreateJwtMlDsa87TestVector().private_seed_bytes}));

TEST_P(JwtMlDsaPrivateKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<JwtMlDsaParameters> parameters =
      JwtMlDsaParameters::Create(test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  JwtMlDsaPublicKey::Builder builder =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicKeyBytes(test_case.public_key_bytes);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }
  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_seed = RestrictedData(test_case.private_key_bytes,
                                               InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtMlDsaPrivateKey> private_key = JwtMlDsaPrivateKey::Create(
      *public_key, private_seed, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetKid(), Eq(test_case.expected_kid));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetPrivateSeedBytes(GetPartialKeyAccess()),
              Eq(private_seed));
}

TEST(JwtMlDsaPrivateKeyTest, CreateInvalidPrivateSeedLengthFails) {
  absl::StatusOr<JwtMlDsaParameters> parameters =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kIgnored,
                                 JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  std::string seed =
      jwt_internal::CreateJwtMlDsa44TestVector().private_seed_bytes;

  RestrictedData long_private_seed =
      RestrictedData(absl::StrCat("ff", seed), InsecureSecretKeyAccess::Get());

  RestrictedData short_private_seed =
      RestrictedData(seed.substr(2), InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      JwtMlDsaPrivateKey::Create(*public_key, long_private_seed,
                                 GetPartialKeyAccess()),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "Private key length 34 is different from expected length 32")));
  EXPECT_THAT(
      JwtMlDsaPrivateKey::Create(*public_key, short_private_seed,
                                 GetPartialKeyAccess()),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "Private key length 30 is different from expected length 32")));
}

TEST(JwtMlDsaPrivateKeyTest, CreateMismatchedKeyPairFails) {
  absl::StatusOr<JwtMlDsaParameters> parameters =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kIgnored,
                                 JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  std::string mismatched_seed =
      jwt_internal::CreateJwtMlDsa44TestVector().private_seed_bytes;
  mismatched_seed[0] ^= 1;

  RestrictedData other_private_seed =
      RestrictedData(mismatched_seed, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      JwtMlDsaPrivateKey::Create(*public_key, other_private_seed,
                                 GetPartialKeyAccess()),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("ML-DSA public key doesn't match the private key")));
}

TEST_P(JwtMlDsaPrivateKeyTest, PrivateKeyEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<JwtMlDsaParameters> parameters =
      JwtMlDsaParameters::Create(test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  JwtMlDsaPublicKey::Builder builder =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicKeyBytes(test_case.public_key_bytes);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }
  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_seed = RestrictedData(test_case.private_key_bytes,
                                               InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtMlDsaPrivateKey> private_key = JwtMlDsaPrivateKey::Create(
      *public_key, private_seed, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<JwtMlDsaPrivateKey> other_private_key =
      JwtMlDsaPrivateKey::Create(*public_key, private_seed,
                                 GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST(JwtMlDsaPrivateKeyTest, DifferentPublicKeyNotEqual) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> other_public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes)
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  RestrictedData private_seed = RestrictedData(
      jwt_internal::CreateJwtMlDsa44TestVector().private_seed_bytes,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtMlDsaPrivateKey> private_key = JwtMlDsaPrivateKey::Create(
      *public_key, private_seed, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<JwtMlDsaPrivateKey> other_private_key =
      JwtMlDsaPrivateKey::Create(*other_public_key, private_seed,
                                 GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key != *other_private_key);
  EXPECT_TRUE(*other_private_key != *private_key);
  EXPECT_FALSE(*private_key == *other_private_key);
  EXPECT_FALSE(*other_private_key == *private_key);
}

TEST(JwtMlDsaPrivateKeyTest, DifferentKeyTypesNotEqual) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_seed = RestrictedData(
      jwt_internal::CreateJwtMlDsa44TestVector().private_seed_bytes,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtMlDsaPrivateKey> private_key = JwtMlDsaPrivateKey::Create(
      *public_key, private_seed, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key != *public_key);
  EXPECT_TRUE(*public_key != *private_key);
  EXPECT_FALSE(*private_key == *public_key);
  EXPECT_FALSE(*public_key == *private_key);
}

TEST(JwtMlDsaPrivateKeyTest, Clone) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_seed = RestrictedData(
      jwt_internal::CreateJwtMlDsa44TestVector().private_seed_bytes,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtMlDsaPrivateKey> private_key = JwtMlDsaPrivateKey::Create(
      *public_key, private_seed, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = private_key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*private_key));
}

TEST(JwtMlDsaPrivateKeyTest, CopyConstructor) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_seed = RestrictedData(
      jwt_internal::CreateJwtMlDsa44TestVector().private_seed_bytes,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtMlDsaPrivateKey> private_key = JwtMlDsaPrivateKey::Create(
      *public_key, private_seed, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  JwtMlDsaPrivateKey copy(*private_key);

  EXPECT_THAT(copy, Eq(*private_key));
}

TEST(JwtMlDsaPrivateKeyTest, CopyAssignment) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_seed = RestrictedData(
      jwt_internal::CreateJwtMlDsa44TestVector().private_seed_bytes,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtMlDsaPrivateKey> private_key = JwtMlDsaPrivateKey::Create(
      *public_key, private_seed, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<JwtMlDsaParameters> other_parameters =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kIgnored,
                                 JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(other_parameters, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> other_public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*other_parameters)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa65TestVector().public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  RestrictedData other_private_seed = RestrictedData(
      jwt_internal::CreateJwtMlDsa65TestVector().private_seed_bytes,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtMlDsaPrivateKey> copy = JwtMlDsaPrivateKey::Create(
      *other_public_key, other_private_seed, GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *private_key;

  EXPECT_THAT(*copy, Eq(*private_key));
}

TEST(JwtMlDsaPrivateKeyTest, MoveConstructor) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_seed = RestrictedData(
      jwt_internal::CreateJwtMlDsa44TestVector().private_seed_bytes,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtMlDsaPrivateKey> private_key = JwtMlDsaPrivateKey::Create(
      *public_key, private_seed, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  JwtMlDsaPrivateKey expected(*private_key);
  JwtMlDsaPrivateKey moved(std::move(*private_key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(JwtMlDsaPrivateKeyTest, MoveAssignment) {
  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
      JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa44TestVector().public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_seed = RestrictedData(
      jwt_internal::CreateJwtMlDsa44TestVector().private_seed_bytes,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtMlDsaPrivateKey> private_key = JwtMlDsaPrivateKey::Create(
      *public_key, private_seed, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<JwtMlDsaParameters> other_parameters =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kIgnored,
                                 JwtMlDsaParameters::Algorithm::kMlDsa65);
  ASSERT_THAT(other_parameters, IsOk());

  absl::StatusOr<JwtMlDsaPublicKey> other_public_key =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*other_parameters)
          .SetPublicKeyBytes(
              jwt_internal::CreateJwtMlDsa65TestVector().public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  RestrictedData other_private_seed = RestrictedData(
      jwt_internal::CreateJwtMlDsa65TestVector().private_seed_bytes,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtMlDsaPrivateKey> moved = JwtMlDsaPrivateKey::Create(
      *other_public_key, other_private_seed, GetPartialKeyAccess());
  ASSERT_THAT(moved, IsOk());

  JwtMlDsaPrivateKey expected(*private_key);
  *moved = std::move(*private_key);

  EXPECT_THAT(*moved, Eq(expected));
}
#endif  // TINK_USE_ONLY_FIPS

}  // namespace
}  // namespace tink
}  // namespace crypto
