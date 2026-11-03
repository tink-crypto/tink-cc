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

#include "tink/signature/subtle/create_ml_dsa_sign_prehash.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/ml_dsa_verify_boringssl.h"
#include "tink/signature/internal/testing/ml_dsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/sign_prehash.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::CreateMlDsaTestVectors;
using ::crypto::tink::internal::GetMlDsaTestVector;
using ::crypto::tink::internal::IsFipsEnabledInSsl;
using ::crypto::tink::internal::IsFipsModeEnabled;
using ::crypto::tink::internal::NewMlDsaVerifyBoringSsl;
using ::crypto::tink::internal::SignatureTestVector;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::StartsWith;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

class CreateMlDsaSignPrehashTestVectorTest
    : public TestWithParam<SignatureTestVector> {
 protected:
  void SetUp() override {
    if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
      GTEST_SKIP()
          << "kRequiresBoringCrypto is set but BoringCrypto is unavailable.";
    }
  }
};

INSTANTIATE_TEST_SUITE_P(CreateMlDsaSignPrehashTestVectorTests,
                         CreateMlDsaSignPrehashTestVectorTest,
                         ValuesIn(CreateMlDsaTestVectors()));

TEST_P(CreateMlDsaSignPrehashTestVectorTest, SignPrehashAndVerifyTestVectors) {
  const SignatureTestVector& test_vector = GetParam();
  ASSERT_TRUE(test_vector.prehash.has_value());
  const auto* private_key = dynamic_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());

  absl::StatusOr<std::unique_ptr<SignPrehash>> prehash_signer =
      CreateMlDsaSignPrehash(*private_key);
  ASSERT_THAT(prehash_signer, IsOk());

  absl::StatusOr<std::string> signature =
      (*prehash_signer)->Sign(*test_vector.prehash);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT(*signature, StartsWith(private_key->GetOutputPrefix()));
  EXPECT_EQ(signature->size(), test_vector.signature.size());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyBoringSsl(private_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, test_vector.message), IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "wrong_message"), Not(IsOk()));
}

TEST_P(CreateMlDsaSignPrehashTestVectorTest, SignPrehashIsNonDeterministic) {
  const SignatureTestVector& test_vector = GetParam();
  ASSERT_TRUE(test_vector.prehash.has_value());
  const auto* private_key = dynamic_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());

  absl::StatusOr<std::unique_ptr<SignPrehash>> prehash_signer =
      CreateMlDsaSignPrehash(*private_key);
  ASSERT_THAT(prehash_signer, IsOk());

  absl::StatusOr<std::string> first_signature =
      (*prehash_signer)->Sign(*test_vector.prehash);
  ASSERT_THAT(first_signature, IsOk());

  absl::StatusOr<std::string> second_signature =
      (*prehash_signer)->Sign(*test_vector.prehash);
  ASSERT_THAT(second_signature, IsOk());

  EXPECT_NE(*first_signature, *second_signature);
}

TEST_P(CreateMlDsaSignPrehashTestVectorTest,
       SignPrehashWithInvalidPrefixFails) {
  const SignatureTestVector& test_vector = GetParam();
  ASSERT_TRUE(test_vector.prehash.has_value());
  const auto* private_key = dynamic_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());
  if (!private_key->GetIdRequirement().has_value()) {
    return;
  }

  absl::StatusOr<std::unique_ptr<SignPrehash>> prehash_signer =
      CreateMlDsaSignPrehash(*private_key);
  ASSERT_THAT(prehash_signer, IsOk());

  std::string invalid_prehash = *test_vector.prehash;
  invalid_prehash[1] ^= 0xff;

  EXPECT_THAT((*prehash_signer)->Sign(invalid_prehash).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(CreateMlDsaSignPrehashTestVectorTest,
       SignPrehashWithInvalidLengthFails) {
  const SignatureTestVector& test_vector = GetParam();
  const auto* private_key = dynamic_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());

  absl::StatusOr<std::unique_ptr<SignPrehash>> prehash_signer =
      CreateMlDsaSignPrehash(*private_key);
  ASSERT_THAT(prehash_signer, IsOk());

  EXPECT_THAT((*prehash_signer)->Sign("short_prehash").status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateMlDsaSignPrehashSingleTest, FipsModeWithoutBoringCryptoFails) {
  if (!IsFipsModeEnabled() || IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  const SignatureTestVector& test_vector = GetMlDsaTestVector(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  const auto* private_key = dynamic_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());

  EXPECT_THAT(CreateMlDsaSignPrehash(*private_key).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
