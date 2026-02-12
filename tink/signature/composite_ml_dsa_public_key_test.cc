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

#include "tink/signature/composite_ml_dsa_public_key.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/internal/util.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/internal/testing/composite_ml_dsa_test_util.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/signature_private_key.h"
#include "tink/signature/signature_public_key.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::GenerateClassicalPrivateKeyForTestOrDie;
using ::crypto::tink::internal::GenerateMlDsaPrivateKeyForTestOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  CompositeMlDsaParameters::MlDsaInstance ml_dsa_instance;
  CompositeMlDsaParameters::ClassicalAlgorithm classical_algorithm;
  CompositeMlDsaParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using CompositeMlDsaPublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    CompositeMlDsaPublicKeyTestSuite, CompositeMlDsaPublicKeyTest,
    Values(TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
                    CompositeMlDsaParameters::Variant::kNoPrefix, absl::nullopt,
                    ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
                    CompositeMlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
                    CompositeMlDsaParameters::Variant::kNoPrefix, absl::nullopt,
                    ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
                    CompositeMlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    CompositeMlDsaParameters::Variant::kNoPrefix, absl::nullopt,
                    ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    CompositeMlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
                    CompositeMlDsaParameters::Variant::kNoPrefix, absl::nullopt,
                    ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
                    CompositeMlDsaParameters::Variant::kNoPrefix, absl::nullopt,
                    ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1,
                    CompositeMlDsaParameters::Variant::kNoPrefix, absl::nullopt,
                    ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1,
                    CompositeMlDsaParameters::Variant::kNoPrefix, absl::nullopt,
                    ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    CompositeMlDsaParameters::Variant::kNoPrefix, absl::nullopt,
                    ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    CompositeMlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
                    CompositeMlDsaParameters::Variant::kNoPrefix, absl::nullopt,
                    ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
                    CompositeMlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)}));

MlDsaPublicKey GenerateMlDsaPublicKeyOrDie(
    CompositeMlDsaParameters::MlDsaInstance instance) {
  return GenerateMlDsaPrivateKeyForTestOrDie(instance).GetPublicKey();
}

std::unique_ptr<SignaturePublicKey> GenerateClassicalPublicKeyOrDie(
    CompositeMlDsaParameters::ClassicalAlgorithm algorithm, bool random) {
  std::unique_ptr<SignaturePrivateKey> private_key =
      GenerateClassicalPrivateKeyForTestOrDie(algorithm, random);
  return crypto::tink::internal::CloneKeyOrDie<SignaturePublicKey>(
      private_key->GetPublicKey());
}

TEST_P(CompositeMlDsaPublicKeyTest, CreatePublicKeyWorks) {
  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey ml_dsa_public_key =
      GenerateMlDsaPublicKeyOrDie(test_case.ml_dsa_instance);
  std::unique_ptr<SignaturePublicKey> classical_public_key =
      GenerateClassicalPublicKeyOrDie(test_case.classical_algorithm,
                                      /*random=*/false);

  std::unique_ptr<SignaturePublicKey> expected_classical_public_key =
      crypto::tink::internal::CloneKeyOrDie<SignaturePublicKey>(
          *classical_public_key);

  absl::StatusOr<CompositeMlDsaPublicKey> public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key, std::move(classical_public_key),
          test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(public_key->GetMlDsaPublicKey(), Eq(ml_dsa_public_key));
  EXPECT_TRUE(public_key->GetClassicalPublicKey() ==
              *expected_classical_public_key);
}

TEST_P(CompositeMlDsaPublicKeyTest,
       CreateKeyWithNoIdRequirementWithTinkParamsFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          test_case.ml_dsa_instance, test_case.classical_algorithm,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey ml_dsa_public_key =
      GenerateMlDsaPublicKeyOrDie(test_case.ml_dsa_instance);
  std::unique_ptr<SignaturePublicKey> classical_public_key =
      GenerateClassicalPublicKeyOrDie(test_case.classical_algorithm,
                                      /*random=*/false);

  EXPECT_THAT(CompositeMlDsaPublicKey::Create(*parameters, ml_dsa_public_key,
                                              std::move(classical_public_key),
                                              /*id_requirement=*/absl::nullopt,
                                              GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("key without ID requirement with parameters "
                                 "with ID requirement")));
}

TEST_P(CompositeMlDsaPublicKeyTest,
       CreateKeyWithIdRequirementWithNoPrefixParamsFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          test_case.ml_dsa_instance, test_case.classical_algorithm,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey ml_dsa_public_key =
      GenerateMlDsaPublicKeyOrDie(test_case.ml_dsa_instance);
  std::unique_ptr<SignaturePublicKey> classical_public_key =
      GenerateClassicalPublicKeyOrDie(test_case.classical_algorithm,
                                      /*random=*/false);

  EXPECT_THAT(
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key, std::move(classical_public_key),
          /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("key with ID requirement with parameters without ID "
                         "requirement")));
}

TEST(CompositeMlDsaPublicKeyTest, CreateWithUnmatchedMlDsaFails) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey ml_dsa_public_key = GenerateMlDsaPublicKeyOrDie(
      CompositeMlDsaParameters::MlDsaInstance::kMlDsa87);
  std::unique_ptr<SignaturePublicKey> classical_public_key =
      GenerateClassicalPublicKeyOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
          /*random=*/false);

  EXPECT_THAT(
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key, std::move(classical_public_key),
          /*id_requirement=*/absl::nullopt, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("ML-DSA public key does not match parameters")));
}

TEST(CompositeMlDsaPublicKeyTest, CreateWithUnmatchedClassicalFails) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey ml_dsa_public_key = GenerateMlDsaPublicKeyOrDie(
      CompositeMlDsaParameters::MlDsaInstance::kMlDsa65);
  std::unique_ptr<SignaturePublicKey> classical_public_key =
      GenerateClassicalPublicKeyOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
          /*random=*/false);

  EXPECT_THAT(
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key, std::move(classical_public_key),
          /*id_requirement=*/absl::nullopt, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Classical public key does not match parameters")));
}

TEST_P(CompositeMlDsaPublicKeyTest, PublicKeyEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey ml_dsa_public_key =
      GenerateMlDsaPublicKeyOrDie(test_case.ml_dsa_instance);
  std::unique_ptr<SignaturePublicKey> classical_public_key =
      GenerateClassicalPublicKeyOrDie(test_case.classical_algorithm,
                                      /*random=*/false);
  std::unique_ptr<SignaturePublicKey> classical_public_key_clone =
      crypto::tink::internal::CloneKeyOrDie<SignaturePublicKey>(
          *classical_public_key);

  absl::StatusOr<CompositeMlDsaPublicKey> public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key, std::move(classical_public_key),
          test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<CompositeMlDsaPublicKey> other_public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key, std::move(classical_public_key_clone),
          test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST_P(CompositeMlDsaPublicKeyTest, DifferentMlDsaPublicKeyNotEqual) {
  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey ml_dsa_public_key1 =
      GenerateMlDsaPublicKeyOrDie(test_case.ml_dsa_instance);
  MlDsaPublicKey ml_dsa_public_key2 =
      GenerateMlDsaPublicKeyOrDie(test_case.ml_dsa_instance);
  std::unique_ptr<SignaturePublicKey> classical_public_key =
      GenerateClassicalPublicKeyOrDie(test_case.classical_algorithm,
                                      /*random=*/false);
  std::unique_ptr<SignaturePublicKey> classical_public_key_clone =
      crypto::tink::internal::CloneKeyOrDie<SignaturePublicKey>(
          *classical_public_key);

  absl::StatusOr<CompositeMlDsaPublicKey> public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key1, std::move(classical_public_key),
          test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<CompositeMlDsaPublicKey> other_public_key =
      CompositeMlDsaPublicKey::Create(*parameters, ml_dsa_public_key2,
                                      std::move(classical_public_key_clone),
                                      test_case.id_requirement,
                                      GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST_P(CompositeMlDsaPublicKeyTest, DifferentClassicalPublicKeyNotEqual) {
  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey ml_dsa_public_key =
      GenerateMlDsaPublicKeyOrDie(test_case.ml_dsa_instance);
  std::unique_ptr<SignaturePublicKey> classical_public_key1 =
      GenerateClassicalPublicKeyOrDie(test_case.classical_algorithm,
                                      /*random=*/false);
  std::unique_ptr<SignaturePublicKey> classical_public_key2 =
      GenerateClassicalPublicKeyOrDie(test_case.classical_algorithm,
                                      /*random=*/true);

  absl::StatusOr<CompositeMlDsaPublicKey> public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key, std::move(classical_public_key1),
          test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<CompositeMlDsaPublicKey> other_public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key, std::move(classical_public_key2),
          test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST_P(CompositeMlDsaPublicKeyTest, DifferentIdRequirementNotEqual) {
  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          test_case.ml_dsa_instance, test_case.classical_algorithm,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey ml_dsa_public_key =
      GenerateMlDsaPublicKeyOrDie(test_case.ml_dsa_instance);
  std::unique_ptr<SignaturePublicKey> classical_public_key =
      GenerateClassicalPublicKeyOrDie(test_case.classical_algorithm,
                                      /*random=*/false);
  std::unique_ptr<SignaturePublicKey> classical_public_key_clone =
      crypto::tink::internal::CloneKeyOrDie<SignaturePublicKey>(
          *classical_public_key);

  absl::StatusOr<CompositeMlDsaPublicKey> public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key, std::move(classical_public_key),
          /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<CompositeMlDsaPublicKey> other_public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key, std::move(classical_public_key_clone),
          /*id_requirement=*/456, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(CompositeMlDsaPublicKeyTest, Clone) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey ml_dsa_public_key = GenerateMlDsaPublicKeyOrDie(
      CompositeMlDsaParameters::MlDsaInstance::kMlDsa65);
  std::unique_ptr<SignaturePublicKey> classical_public_key =
      GenerateClassicalPublicKeyOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          /*random=*/false);

  absl::StatusOr<CompositeMlDsaPublicKey> public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key, std::move(classical_public_key),
          /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  std::unique_ptr<Key> cloned_key = public_key->Clone();
  EXPECT_THAT(*cloned_key, Eq(*public_key));
}

TEST(CompositeMlDsaPublicKeyTest, CopyConstructor) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey ml_dsa_public_key = GenerateMlDsaPublicKeyOrDie(
      CompositeMlDsaParameters::MlDsaInstance::kMlDsa65);
  std::unique_ptr<SignaturePublicKey> classical_public_key =
      GenerateClassicalPublicKeyOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          /*random=*/false);

  absl::StatusOr<CompositeMlDsaPublicKey> public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key, std::move(classical_public_key),
          /*id_requirement=*/123, GetPartialKeyAccess());

  CompositeMlDsaPublicKey copy(*public_key);
  EXPECT_THAT(copy, Eq(*public_key));
}

TEST(CompositeMlDsaPublicKeyTest, CopyAssignment) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey ml_dsa_public_key = GenerateMlDsaPublicKeyOrDie(
      CompositeMlDsaParameters::MlDsaInstance::kMlDsa65);
  std::unique_ptr<SignaturePublicKey> classical_public_key =
      GenerateClassicalPublicKeyOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          /*random=*/false);

  absl::StatusOr<CompositeMlDsaPublicKey> public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key, std::move(classical_public_key),
          /*id_requirement=*/123, GetPartialKeyAccess());

  absl::StatusOr<CompositeMlDsaParameters> other_parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey other_ml_dsa_public_key = GenerateMlDsaPublicKeyOrDie(
      CompositeMlDsaParameters::MlDsaInstance::kMlDsa87);
  std::unique_ptr<SignaturePublicKey> other_classical_public_key =
      GenerateClassicalPublicKeyOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
          /*random=*/false);

  absl::StatusOr<CompositeMlDsaPublicKey> copy =
      CompositeMlDsaPublicKey::Create(
          *other_parameters, other_ml_dsa_public_key,
          std::move(other_classical_public_key),
          /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *public_key;

  EXPECT_THAT(*copy, Eq(*public_key));
  EXPECT_THAT(copy->GetOutputPrefix(), Eq(public_key->GetOutputPrefix()));
}

TEST(CompositeMlDsaPublicKeyTest, MoveConstructor) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey ml_dsa_public_key = GenerateMlDsaPublicKeyOrDie(
      CompositeMlDsaParameters::MlDsaInstance::kMlDsa65);
  std::unique_ptr<SignaturePublicKey> classical_public_key =
      GenerateClassicalPublicKeyOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          /*random=*/false);

  absl::StatusOr<CompositeMlDsaPublicKey> public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key, std::move(classical_public_key),
          /*id_requirement=*/123, GetPartialKeyAccess());

  CompositeMlDsaPublicKey expected(*public_key);
  CompositeMlDsaPublicKey moved(std::move(*public_key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(CompositeMlDsaPublicKeyTest, MoveAssignment) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey ml_dsa_public_key = GenerateMlDsaPublicKeyOrDie(
      CompositeMlDsaParameters::MlDsaInstance::kMlDsa65);
  std::unique_ptr<SignaturePublicKey> classical_public_key =
      GenerateClassicalPublicKeyOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          /*random=*/false);

  absl::StatusOr<CompositeMlDsaPublicKey> public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, ml_dsa_public_key, std::move(classical_public_key),
          /*id_requirement=*/123, GetPartialKeyAccess());

  absl::StatusOr<CompositeMlDsaParameters> other_parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  MlDsaPublicKey other_ml_dsa_public_key = GenerateMlDsaPublicKeyOrDie(
      CompositeMlDsaParameters::MlDsaInstance::kMlDsa87);
  std::unique_ptr<SignaturePublicKey> other_classical_public_key =
      GenerateClassicalPublicKeyOrDie(
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
          /*random=*/false);

  absl::StatusOr<CompositeMlDsaPublicKey> moved =
      CompositeMlDsaPublicKey::Create(
          *other_parameters, other_ml_dsa_public_key,
          std::move(other_classical_public_key),
          /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(moved, IsOk());

  CompositeMlDsaPublicKey expected(*public_key);
  *moved = std::move(*public_key);

  EXPECT_THAT(*moved, Eq(expected));
  EXPECT_THAT(moved->GetOutputPrefix(), Eq(expected.GetOutputPrefix()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
