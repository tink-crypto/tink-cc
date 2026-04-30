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

#include "tink/signature/subtle/composite_ml_dsa_verify_boringssl.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/fips_utils.h"
#include "tink/low_level_crypto_access.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/composite_ml_dsa_private_key.h"
#include "tink/signature/internal/testing/composite_ml_dsa_test_util.h"
#include "tink/signature/internal/testing/composite_ml_dsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/subtle/composite_ml_dsa_sign_boringssl.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::crypto::tink::CompositeMlDsaParameters;
using ::crypto::tink::PublicKeyVerify;
using ::crypto::tink::internal::GenerateCompositeMlDsaPrivateKeyForTestOrDie;
using ::crypto::tink::internal::IsFipsModeEnabled;
using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;
using ::testing::ValuesIn;

struct TestCase {
  CompositeMlDsaParameters::MlDsaInstance ml_dsa_instance;
  CompositeMlDsaParameters::ClassicalAlgorithm classical_algorithm;
};

using CompositeMlDsaVerifyBoringSslTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    CompositeMlDsaVerifyTestSuite, CompositeMlDsaVerifyBoringSslTest,
    Values(
        TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                 CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519},
        TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                 CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256},
        TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                 CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384},
        TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                 CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss},
        TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                 CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss},
        TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                 CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1},
        TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                 CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1},
        TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                 CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384},
        TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                 CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521},
        TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                 CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss},
        TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                 CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss}));

TEST_P(CompositeMlDsaVerifyBoringSslTest, BasicSignVerifyRawWorks) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          test_case.ml_dsa_instance, test_case.classical_algorithm,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaPrivateKey composite_ml_dsa_private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false,
          /*id_requirement=*/absl::nullopt);

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer = NewCompositeMlDsaSign(
      composite_ml_dsa_private_key, GetLowLevelCryptoAccess());
  ASSERT_THAT(signer, IsOk());

  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewCompositeMlDsaVerify(composite_ml_dsa_private_key.GetPublicKey(),
                              GetLowLevelCryptoAccess());
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

TEST_P(CompositeMlDsaVerifyBoringSslTest, BasicSignVerifyTinkWorks) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          test_case.ml_dsa_instance, test_case.classical_algorithm,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaPrivateKey composite_ml_dsa_private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false,
          /*id_requirement=*/0x02030400);

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer = NewCompositeMlDsaSign(
      composite_ml_dsa_private_key, GetLowLevelCryptoAccess());
  ASSERT_THAT(signer, IsOk());

  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewCompositeMlDsaVerify(composite_ml_dsa_private_key.GetPublicKey(),
                              GetLowLevelCryptoAccess());
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

TEST_P(CompositeMlDsaVerifyBoringSslTest, VerifyWithWrongSignatureFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          test_case.ml_dsa_instance, test_case.classical_algorithm,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaPrivateKey composite_ml_dsa_private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false,
          /*id_requirement=*/absl::nullopt);

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewCompositeMlDsaVerify(composite_ml_dsa_private_key.GetPublicKey(),
                              GetLowLevelCryptoAccess());
  ASSERT_THAT(verifier, IsOk());

  absl::string_view message = "message to be signed";
  EXPECT_THAT((*verifier)->Verify("wrong_signature", message),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Signature is too short.")));
}

TEST_P(CompositeMlDsaVerifyBoringSslTest, VerifyWithModifiedSignatureFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          test_case.ml_dsa_instance, test_case.classical_algorithm,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaPrivateKey composite_ml_dsa_private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false,
          /*id_requirement=*/absl::nullopt);

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer = NewCompositeMlDsaSign(
      composite_ml_dsa_private_key, GetLowLevelCryptoAccess());
  ASSERT_THAT(signer, IsOk());

  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewCompositeMlDsaVerify(composite_ml_dsa_private_key.GetPublicKey(),
                              GetLowLevelCryptoAccess());
  ASSERT_THAT(verifier, IsOk());

  // Verify the valid signature works.
  ASSERT_THAT((*verifier)->Verify(*signature, message), IsOk());

  // Signature too short.
  std::string too_short_signature =
      signature->substr(0, signature->size() - 1);
  EXPECT_THAT((*verifier)->Verify(too_short_signature, message),
              Not(IsOk()));

  // Signature with trailing bytes appended must be rejected.
  std::string too_big_signature = *signature + "00";
  EXPECT_THAT((*verifier)->Verify(too_big_signature, message), Not(IsOk()));

  // Invalidate one byte of the signature.
  (*signature)[10] ^= 1;
  EXPECT_THAT((*verifier)->Verify(*signature, message), Not(IsOk()));
}

TEST_P(CompositeMlDsaVerifyBoringSslTest, VerifyWithModifiedOutputPrefixFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          test_case.ml_dsa_instance, test_case.classical_algorithm,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaPrivateKey composite_ml_dsa_private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false,
          /*id_requirement=*/0x02030400);

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer = NewCompositeMlDsaSign(
      composite_ml_dsa_private_key, GetLowLevelCryptoAccess());
  ASSERT_THAT(signer, IsOk());

  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewCompositeMlDsaVerify(composite_ml_dsa_private_key.GetPublicKey(),
                              GetLowLevelCryptoAccess());
  ASSERT_THAT(verifier, IsOk());

  // Invalidate one byte of the output prefix.
  (*signature)[0] ^= 1;
  EXPECT_THAT((*verifier)->Verify(*signature, message), Not(IsOk()));
}

TEST_P(CompositeMlDsaVerifyBoringSslTest, VerifyWithWrongMessageFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          test_case.ml_dsa_instance, test_case.classical_algorithm,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaPrivateKey composite_ml_dsa_private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false,
          /*id_requirement=*/absl::nullopt);

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer = NewCompositeMlDsaSign(
      composite_ml_dsa_private_key, GetLowLevelCryptoAccess());
  ASSERT_THAT(signer, IsOk());

  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewCompositeMlDsaVerify(composite_ml_dsa_private_key.GetPublicKey(),
                              GetLowLevelCryptoAccess());
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(*signature, "wrong_message"), Not(IsOk()));
}

TEST_P(CompositeMlDsaVerifyBoringSslTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is true.";
  }

  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          test_case.ml_dsa_instance, test_case.classical_algorithm,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaPrivateKey composite_ml_dsa_private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false,
          /*id_requirement=*/absl::nullopt);

  // Check that creating the verifier fails in FIPS mode.
  EXPECT_THAT(
      NewCompositeMlDsaVerify(composite_ml_dsa_private_key.GetPublicKey(),
                              GetLowLevelCryptoAccess())
          .status(),
      StatusIs(absl::StatusCode::kInternal));
}

using CompositeMlDsaTestVectorTest =
    testing::TestWithParam<internal::SignatureTestVector>;

TEST_P(CompositeMlDsaTestVectorTest, TestVectorSignVerify) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  internal::SignatureTestVector param = GetParam();

  const CompositeMlDsaPrivateKey* composite_ml_dsa_private_key =
      dynamic_cast<CompositeMlDsaPrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(composite_ml_dsa_private_key, NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer = NewCompositeMlDsaSign(
      *composite_ml_dsa_private_key, GetLowLevelCryptoAccess());
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::string> signature = (*signer)->Sign(param.message);
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewCompositeMlDsaVerify(composite_ml_dsa_private_key->GetPublicKey(),
                              GetLowLevelCryptoAccess());
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(*signature, param.message), IsOk());

  EXPECT_THAT((*verifier)->Verify(param.signature, param.message), IsOk());
}

INSTANTIATE_TEST_SUITE_P(CompositeMlDsaTestVectorTestSuite,
                         CompositeMlDsaTestVectorTest,
                         ValuesIn(internal::CreateCompositeMlDsaTestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
