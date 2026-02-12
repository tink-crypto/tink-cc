// Copyright 2026 Google LLC
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

#include "tink/signature/composite_ml_dsa_private_key.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/internal/util.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/internal/testing/composite_ml_dsa_test_util.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/signature_private_key.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::GenerateClassicalPrivateKeyForTestOrDie;
using ::crypto::tink::internal::GenerateMlDsaPrivateKeyForTestOrDie;
using ::crypto::tink::test::IsOk;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  CompositeMlDsaParameters::MlDsaInstance ml_dsa_instance;
  CompositeMlDsaParameters::ClassicalAlgorithm classical_algorithm;
  CompositeMlDsaParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using CompositeMlDsaPrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    CompositeMlDsaPrivateKeyTestSuite, CompositeMlDsaPrivateKeyTest,
    Values(TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
                    CompositeMlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
                    CompositeMlDsaParameters::Variant::kNoPrefix, absl::nullopt,
                    ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
                    CompositeMlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
                    CompositeMlDsaParameters::Variant::kNoPrefix, absl::nullopt,
                    ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    CompositeMlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    CompositeMlDsaParameters::Variant::kNoPrefix, absl::nullopt,
                    ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
                    CompositeMlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
                    CompositeMlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1,
                    CompositeMlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1,
                    CompositeMlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    CompositeMlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    CompositeMlDsaParameters::Variant::kNoPrefix, absl::nullopt,
                    ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
                    CompositeMlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
                    CompositeMlDsaParameters::Variant::kNoPrefix, absl::nullopt,
                    ""}));

TEST_P(CompositeMlDsaPrivateKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPrivateKey ml_dsa_private_key =
      GenerateMlDsaPrivateKeyForTestOrDie(test_case.ml_dsa_instance);

  std::unique_ptr<SignaturePrivateKey> classical_private_key =
      GenerateClassicalPrivateKeyForTestOrDie(test_case.classical_algorithm,
                                              /*force_random=*/false);

  std::unique_ptr<SignaturePrivateKey> classical_private_key_clone =
      crypto::tink::internal::CloneKeyOrDie<SignaturePrivateKey>(
          *classical_private_key);

  absl::StatusOr<CompositeMlDsaPrivateKey> private_key =
      CompositeMlDsaPrivateKey::Create(
          *parameters, ml_dsa_private_key, std::move(classical_private_key),
          test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetMlDsaPrivateKey(), Eq(ml_dsa_private_key));
  EXPECT_TRUE(private_key->GetClassicalPrivateKey() ==
              *classical_private_key_clone);
}

TEST_P(CompositeMlDsaPrivateKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPrivateKey ml_dsa_private_key =
      GenerateMlDsaPrivateKeyForTestOrDie(test_case.ml_dsa_instance);

  std::unique_ptr<SignaturePrivateKey> classical_private_key =
      GenerateClassicalPrivateKeyForTestOrDie(test_case.classical_algorithm,
                                              /*force_random=*/false);

  std::unique_ptr<SignaturePrivateKey> classical_private_key_clone =
      crypto::tink::internal::CloneKeyOrDie<SignaturePrivateKey>(
          *classical_private_key);

  absl::StatusOr<CompositeMlDsaPrivateKey> private_key =
      CompositeMlDsaPrivateKey::Create(
          *parameters, ml_dsa_private_key, std::move(classical_private_key),
          test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<CompositeMlDsaPrivateKey> other_private_key =
      CompositeMlDsaPrivateKey::Create(*parameters, ml_dsa_private_key,
                                       std::move(classical_private_key_clone),
                                       test_case.id_requirement,
                                       GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST_P(CompositeMlDsaPrivateKeyTest, DifferentMlDsaPrivateKeyNotEqual) {
  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPrivateKey ml_dsa_private_key1 =
      GenerateMlDsaPrivateKeyForTestOrDie(test_case.ml_dsa_instance);

  MlDsaPrivateKey ml_dsa_private_key2 =
      GenerateMlDsaPrivateKeyForTestOrDie(test_case.ml_dsa_instance);

  std::unique_ptr<SignaturePrivateKey> classical_private_key =
      GenerateClassicalPrivateKeyForTestOrDie(test_case.classical_algorithm,
                                              /*force_random=*/false);

  std::unique_ptr<SignaturePrivateKey> classical_private_key_clone =
      crypto::tink::internal::CloneKeyOrDie<SignaturePrivateKey>(
          *classical_private_key);

  absl::StatusOr<CompositeMlDsaPrivateKey> private_key1 =
      CompositeMlDsaPrivateKey::Create(
          *parameters, ml_dsa_private_key1, std::move(classical_private_key),
          test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(private_key1, IsOk());

  absl::StatusOr<CompositeMlDsaPrivateKey> private_key2 =
      CompositeMlDsaPrivateKey::Create(*parameters, ml_dsa_private_key2,
                                       std::move(classical_private_key_clone),
                                       test_case.id_requirement,
                                       GetPartialKeyAccess());
  ASSERT_THAT(private_key2, IsOk());

  EXPECT_TRUE(*private_key1 != *private_key2);
  EXPECT_TRUE(*private_key2 != *private_key1);
  EXPECT_FALSE(*private_key1 == *private_key2);
  EXPECT_FALSE(*private_key2 == *private_key1);
}

TEST_P(CompositeMlDsaPrivateKeyTest, DifferentClassicalPrivateKeyNotEqual) {
  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPrivateKey ml_dsa_private_key =
      GenerateMlDsaPrivateKeyForTestOrDie(test_case.ml_dsa_instance);

  std::unique_ptr<SignaturePrivateKey> classical_private_key1 =
      GenerateClassicalPrivateKeyForTestOrDie(test_case.classical_algorithm,
                                              /*force_random=*/false);

  std::unique_ptr<SignaturePrivateKey> classical_private_key2 =
      GenerateClassicalPrivateKeyForTestOrDie(test_case.classical_algorithm,
                                              /*force_random=*/true);

  absl::StatusOr<CompositeMlDsaPrivateKey> private_key1 =
      CompositeMlDsaPrivateKey::Create(
          *parameters, ml_dsa_private_key, std::move(classical_private_key1),
          test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(private_key1, IsOk());

  absl::StatusOr<CompositeMlDsaPrivateKey> private_key2 =
      CompositeMlDsaPrivateKey::Create(
          *parameters, ml_dsa_private_key, std::move(classical_private_key2),
          test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(private_key2, IsOk());

  EXPECT_TRUE(*private_key1 != *private_key2);
  EXPECT_TRUE(*private_key2 != *private_key1);
  EXPECT_FALSE(*private_key1 == *private_key2);
  EXPECT_FALSE(*private_key2 == *private_key1);
}

TEST_P(CompositeMlDsaPrivateKeyTest, DifferentIdRequirementNotEqual) {
  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          test_case.ml_dsa_instance, test_case.classical_algorithm,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPrivateKey ml_dsa_private_key =
      GenerateMlDsaPrivateKeyForTestOrDie(test_case.ml_dsa_instance);

  std::unique_ptr<SignaturePrivateKey> classical_private_key =
      GenerateClassicalPrivateKeyForTestOrDie(test_case.classical_algorithm,
                                              /*force_random=*/false);

  std::unique_ptr<SignaturePrivateKey> classical_private_key_clone =
      crypto::tink::internal::CloneKeyOrDie<SignaturePrivateKey>(
          *classical_private_key);

  absl::StatusOr<CompositeMlDsaPrivateKey> private_key1 =
      CompositeMlDsaPrivateKey::Create(
          *parameters, ml_dsa_private_key, std::move(classical_private_key),
          /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(private_key1, IsOk());

  absl::StatusOr<CompositeMlDsaPrivateKey> private_key2 =
      CompositeMlDsaPrivateKey::Create(*parameters, ml_dsa_private_key,
                                       std::move(classical_private_key_clone),
                                       /*id_requirement=*/456,
                                       GetPartialKeyAccess());
  ASSERT_THAT(private_key2, IsOk());

  EXPECT_TRUE(*private_key1 != *private_key2);
  EXPECT_TRUE(*private_key2 != *private_key1);
  EXPECT_FALSE(*private_key1 == *private_key2);
  EXPECT_FALSE(*private_key2 == *private_key1);
}

TEST(CompositeMlDsaPrivateKeyTest, Clone) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPrivateKey ml_dsa_private_key = GenerateMlDsaPrivateKeyForTestOrDie(
      CompositeMlDsaParameters::MlDsaInstance::kMlDsa65);

  std::unique_ptr<SignaturePrivateKey> classical_private_key =
      GenerateClassicalPrivateKeyForTestOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          /*force_random=*/false);

  absl::StatusOr<CompositeMlDsaPrivateKey> private_key =
      CompositeMlDsaPrivateKey::Create(
          *parameters, ml_dsa_private_key, std::move(classical_private_key),
          /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  std::unique_ptr<Key> clone = private_key->Clone();
  EXPECT_THAT(*clone, Eq(*private_key));
}

TEST(CompositeMlDsaPrivateKeyTest, CopyConstructor) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPrivateKey ml_dsa_private_key = GenerateMlDsaPrivateKeyForTestOrDie(
      CompositeMlDsaParameters::MlDsaInstance::kMlDsa65);

  std::unique_ptr<SignaturePrivateKey> classical_private_key =
      GenerateClassicalPrivateKeyForTestOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          /*force_random=*/false);

  absl::StatusOr<CompositeMlDsaPrivateKey> private_key =
      CompositeMlDsaPrivateKey::Create(
          *parameters, ml_dsa_private_key, std::move(classical_private_key),
          /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  CompositeMlDsaPrivateKey copy(*private_key);
  EXPECT_THAT(copy, Eq(*private_key));
}

TEST(CompositeMlDsaPrivateKeyTest, CopyAssignment) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPrivateKey ml_dsa_private_key = GenerateMlDsaPrivateKeyForTestOrDie(
      CompositeMlDsaParameters::MlDsaInstance::kMlDsa65);

  std::unique_ptr<SignaturePrivateKey> classical_private_key =
      GenerateClassicalPrivateKeyForTestOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          /*force_random=*/false);

  absl::StatusOr<CompositeMlDsaPrivateKey> private_key =
      CompositeMlDsaPrivateKey::Create(
          *parameters, ml_dsa_private_key, std::move(classical_private_key),
          /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<CompositeMlDsaParameters> other_parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(other_parameters, IsOk());

  MlDsaPrivateKey other_ml_dsa_private_key =
      GenerateMlDsaPrivateKeyForTestOrDie(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa87);

  std::unique_ptr<SignaturePrivateKey> other_classical_private_key =
      GenerateClassicalPrivateKeyForTestOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
          /*force_random=*/false);

  absl::StatusOr<CompositeMlDsaPrivateKey> copy =
      CompositeMlDsaPrivateKey::Create(
          *other_parameters, other_ml_dsa_private_key,
          std::move(other_classical_private_key), /*id_requirement=*/456,
          GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *private_key;
  EXPECT_THAT(*copy, Eq(*private_key));
}

TEST(CompositeMlDsaPrivateKeyTest, MoveConstructor) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPrivateKey ml_dsa_private_key = GenerateMlDsaPrivateKeyForTestOrDie(
      CompositeMlDsaParameters::MlDsaInstance::kMlDsa65);

  std::unique_ptr<SignaturePrivateKey> classical_private_key =
      GenerateClassicalPrivateKeyForTestOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          /*force_random=*/false);

  absl::StatusOr<CompositeMlDsaPrivateKey> private_key =
      CompositeMlDsaPrivateKey::Create(
          *parameters, ml_dsa_private_key, std::move(classical_private_key),
          /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  CompositeMlDsaPrivateKey expected(*private_key);
  CompositeMlDsaPrivateKey moved(std::move(*private_key));
  EXPECT_THAT(moved, Eq(expected));
}

TEST(CompositeMlDsaPrivateKeyTest, MoveAssignment) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPrivateKey ml_dsa_private_key = GenerateMlDsaPrivateKeyForTestOrDie(
      CompositeMlDsaParameters::MlDsaInstance::kMlDsa65);

  std::unique_ptr<SignaturePrivateKey> classical_private_key =
      GenerateClassicalPrivateKeyForTestOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          /*force_random=*/false);

  absl::StatusOr<CompositeMlDsaPrivateKey> private_key =
      CompositeMlDsaPrivateKey::Create(
          *parameters, ml_dsa_private_key, std::move(classical_private_key),
          /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<CompositeMlDsaParameters> other_parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(other_parameters, IsOk());

  MlDsaPrivateKey other_ml_dsa_private_key =
      GenerateMlDsaPrivateKeyForTestOrDie(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa87);

  std::unique_ptr<SignaturePrivateKey> other_classical_private_key =
      GenerateClassicalPrivateKeyForTestOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
          /*force_random=*/false);

  absl::StatusOr<CompositeMlDsaPrivateKey> moved =
      CompositeMlDsaPrivateKey::Create(
          *other_parameters, other_ml_dsa_private_key,
          std::move(other_classical_private_key), /*id_requirement=*/456,
          GetPartialKeyAccess());
  ASSERT_THAT(moved, IsOk());

  CompositeMlDsaPrivateKey expected(*private_key);
  *moved = std::move(*private_key);
  EXPECT_THAT(*moved, Eq(expected));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
