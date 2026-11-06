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

#include "tink/signature/subtle/create_composite_ml_dsa_verifier.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_verify.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/composite_ml_dsa_private_key.h"
#include "tink/signature/internal/testing/composite_ml_dsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::CreateCompositeMlDsaTestVectors;
using ::crypto::tink::internal::CreateMlDsa65Ed2551TestVector;
using ::crypto::tink::internal::IsFipsModeEnabled;
using ::crypto::tink::internal::SignatureTestVector;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using CreateCompositeMlDsaPublicKeyVerifyTest =
    TestWithParam<SignatureTestVector>;

TEST_P(CreateCompositeMlDsaPublicKeyVerifyTest, VerifyTestVectorsWorks) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  const SignatureTestVector& param = GetParam();
  const auto* private_key = dynamic_cast<const CompositeMlDsaPrivateKey*>(
      param.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateCompositeMlDsaPublicKeyVerify(private_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(param.signature, param.message), IsOk());
}

INSTANTIATE_TEST_SUITE_P(CreateCompositeMlDsaPublicKeyVerifyTests,
                         CreateCompositeMlDsaPublicKeyVerifyTest,
                         ValuesIn(CreateCompositeMlDsaTestVectors()));

TEST(CreateCompositeMlDsaPublicKeyVerifySingleTest,
     VerifyWithWrongMessageFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  SignatureTestVector test_vector = CreateMlDsa65Ed2551TestVector();
  const auto* private_key = dynamic_cast<const CompositeMlDsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateCompositeMlDsaPublicKeyVerify(private_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(test_vector.signature, "wrong_message"),
              Not(IsOk()));
}

TEST(CreateCompositeMlDsaPublicKeyVerifySingleTest,
     VerifyWithModifiedSignatureFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  SignatureTestVector test_vector = CreateMlDsa65Ed2551TestVector();
  const auto* private_key = dynamic_cast<const CompositeMlDsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateCompositeMlDsaPublicKeyVerify(private_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  std::string modified_signature = test_vector.signature;
  modified_signature[modified_signature.size() - 1] ^= 1;
  EXPECT_THAT((*verifier)->Verify(modified_signature, test_vector.message),
              Not(IsOk()));
}

TEST(CreateCompositeMlDsaPublicKeyVerifySingleTest,
     VerifyWithModifiedOutputPrefixFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  SignatureTestVector test_vector =
      CreateMlDsa65Ed2551TestVector(CompositeMlDsaParameters::Variant::kTink);
  const auto* private_key = dynamic_cast<const CompositeMlDsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateCompositeMlDsaPublicKeyVerify(private_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  std::string modified_signature = test_vector.signature;
  modified_signature[0] ^= 1;
  EXPECT_THAT((*verifier)->Verify(modified_signature, test_vector.message),
              Not(IsOk()));
}

TEST(CreateCompositeMlDsaPublicKeyVerifySingleTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is true.";
  }

  SignatureTestVector test_vector = CreateMlDsa65Ed2551TestVector();
  const auto* private_key = dynamic_cast<const CompositeMlDsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());

  EXPECT_THAT(
      CreateCompositeMlDsaPublicKeyVerify(private_key->GetPublicKey()).status(),
      StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
