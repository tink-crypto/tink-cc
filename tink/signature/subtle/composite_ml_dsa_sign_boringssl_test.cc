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

#include "tink/signature/subtle/composite_ml_dsa_sign_boringssl.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/fips_utils.h"
#include "tink/low_level_crypto_access.h"
#include "tink/public_key_sign.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/composite_ml_dsa_private_key.h"
#include "tink/signature/internal/testing/composite_ml_dsa_test_util.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::internal::GenerateCompositeMlDsaPrivateKeyForTestOrDie;
using ::crypto::tink::internal::IsFipsModeEnabled;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::StartsWith;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  CompositeMlDsaParameters::Variant variant;
  CompositeMlDsaParameters::MlDsaInstance ml_dsa_instance;
  CompositeMlDsaParameters::ClassicalAlgorithm classical_algorithm;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using CompositeMlDsaSignBoringSslTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    CompositeMlDsaSignTestSuite, CompositeMlDsaSignBoringSslTest,
    Values(TestCase{CompositeMlDsaParameters::Variant::kNoPrefix,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""},
           TestCase{CompositeMlDsaParameters::Variant::kTink,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
                    /*id_requirement=*/0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::Variant::kNoPrefix,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""},
           TestCase{CompositeMlDsaParameters::Variant::kTink,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
                    /*id_requirement=*/0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::Variant::kNoPrefix,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""},
           TestCase{CompositeMlDsaParameters::Variant::kTink,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    /*id_requirement=*/0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::Variant::kNoPrefix,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""},
           TestCase{CompositeMlDsaParameters::Variant::kTink,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
                    /*id_requirement=*/0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::Variant::kNoPrefix,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""},
           TestCase{CompositeMlDsaParameters::Variant::kTink,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
                    /*id_requirement=*/0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::Variant::kNoPrefix,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""},
           TestCase{CompositeMlDsaParameters::Variant::kTink,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1,
                    /*id_requirement=*/0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::Variant::kNoPrefix,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""},
           TestCase{CompositeMlDsaParameters::Variant::kTink,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1,
                    /*id_requirement=*/0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::Variant::kNoPrefix,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""},
           TestCase{CompositeMlDsaParameters::Variant::kTink,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    /*id_requirement=*/0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::Variant::kNoPrefix,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""},
           TestCase{CompositeMlDsaParameters::Variant::kTink,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
                    /*id_requirement=*/0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::Variant::kNoPrefix,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""},
           TestCase{CompositeMlDsaParameters::Variant::kTink,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
                    /*id_requirement=*/0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::Variant::kNoPrefix,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""},
           TestCase{CompositeMlDsaParameters::Variant::kTink,
                    CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
                    /*id_requirement=*/0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)}));

TEST_P(CompositeMlDsaSignBoringSslTest, SignatureOutputPrefixIsCorrect) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips is false.";
  }

  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaPrivateKey composite_ml_dsa_private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer = NewCompositeMlDsaSign(
      composite_ml_dsa_private_key, GetLowLevelCryptoAccess());
  ASSERT_THAT(signer, IsOk());

  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  EXPECT_THAT(*signature, StartsWith(test_case.output_prefix));
}

TEST_P(CompositeMlDsaSignBoringSslTest, SignatureIsNonDeterministic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips is false.";
  }

  TestCase test_case = GetParam();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaPrivateKey composite_ml_dsa_private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer = NewCompositeMlDsaSign(
      composite_ml_dsa_private_key, GetLowLevelCryptoAccess());
  ASSERT_THAT(signer, IsOk());

  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> first_signature = (*signer)->Sign(message);
  ASSERT_THAT(first_signature, IsOk());
  absl::StatusOr<std::string> second_signature = (*signer)->Sign(message);
  ASSERT_THAT(second_signature, IsOk());

  EXPECT_NE(*first_signature, *second_signature);
}

TEST_P(CompositeMlDsaSignBoringSslTest, FipsMode) {
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

  // Check that creating the signer fails in FIPS mode.
  EXPECT_THAT(NewCompositeMlDsaSign(composite_ml_dsa_private_key,
                                    GetLowLevelCryptoAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
