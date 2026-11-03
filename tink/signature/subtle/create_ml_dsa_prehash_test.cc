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

#include "tink/signature/subtle/create_ml_dsa_prehash.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/internal/fips_utils.h"
#include "tink/signature/internal/testing/ml_dsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/prehash.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::CreateMlDsaTestVectors;
using ::crypto::tink::internal::GetMlDsaTestVector;
using ::crypto::tink::internal::IsFipsEnabledInSsl;
using ::crypto::tink::internal::IsFipsModeEnabled;
using ::crypto::tink::internal::SignatureTestVector;
using ::testing::Ne;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

class CreateMlDsaPrehashTestVectorTest
    : public TestWithParam<SignatureTestVector> {
 protected:
  void SetUp() override {
    if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
      GTEST_SKIP()
          << "kRequiresBoringCrypto is set but BoringCrypto is unavailable.";
    }
  }
};

INSTANTIATE_TEST_SUITE_P(CreateMlDsaPrehashTestVectorTests,
                         CreateMlDsaPrehashTestVectorTest,
                         ValuesIn(CreateMlDsaTestVectors()));

TEST_P(CreateMlDsaPrehashTestVectorTest, PrehashMatchesTestVector) {
  const SignatureTestVector& test_vector = GetParam();
  ASSERT_TRUE(test_vector.prehash.has_value());
  const auto* private_key = dynamic_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher =
      CreateMlDsaPrehash(private_key->GetPublicKey());
  ASSERT_THAT(prehasher, IsOk());

  EXPECT_THAT((*prehasher)->Compute(test_vector.message),
              IsOkAndHolds(*test_vector.prehash));
}

TEST_P(CreateMlDsaPrehashTestVectorTest,
       DifferentMessagesProduceDifferentPrehashes) {
  const SignatureTestVector& test_vector = GetParam();
  ASSERT_TRUE(test_vector.prehash.has_value());
  const auto* private_key = dynamic_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher =
      CreateMlDsaPrehash(private_key->GetPublicKey());
  ASSERT_THAT(prehasher, IsOk());

  EXPECT_THAT((*prehasher)->Compute("different_message"),
              IsOkAndHolds(Ne(*test_vector.prehash)));
}

TEST(CreateMlDsaPrehashSingleTest, FipsModeWithoutBoringCryptoFails) {
  if (!IsFipsModeEnabled() || IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  const SignatureTestVector& test_vector = GetMlDsaTestVector(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  const auto* private_key = dynamic_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());

  EXPECT_THAT(CreateMlDsaPrehash(private_key->GetPublicKey()).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
