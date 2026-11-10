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

#include "tink/signature/internal/ecdsa_prehash_boringssl.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/internal/fips_utils.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/prehash.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::Ne;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

class EcdsaPrehashBoringSslTestVectorTest
    : public TestWithParam<SignatureTestVector> {
 protected:
  void SetUp() override {
    if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
      GTEST_SKIP()
          << "kRequiresBoringCrypto is set but BoringCrypto is unavailable.";
    }
  }
};

INSTANTIATE_TEST_SUITE_P(EcdsaPrehashBoringSslTestVectorTests,
                         EcdsaPrehashBoringSslTestVectorTest,
                         ValuesIn(CreateEcdsaTestVectors()));

TEST_P(EcdsaPrehashBoringSslTestVectorTest, PrehashMatchesTestVector) {
  const SignatureTestVector& test_vector = GetParam();
  const auto* private_key = dynamic_cast<const EcdsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());
  if (!test_vector.prehash.has_value()) {
    EXPECT_THAT(NewEcdsaPrehashBoringSsl(private_key->GetPublicKey()).status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
    return;
  }

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher =
      NewEcdsaPrehashBoringSsl(private_key->GetPublicKey());
  ASSERT_THAT(prehasher, IsOk());

  EXPECT_THAT((*prehasher)->Compute(test_vector.message),
              IsOkAndHolds(*test_vector.prehash));
}

TEST_P(EcdsaPrehashBoringSslTestVectorTest,
       DifferentMessagesProduceDifferentPrehashes) {
  const SignatureTestVector& test_vector = GetParam();
  if (!test_vector.prehash.has_value()) {
    return;
  }
  const auto* private_key = dynamic_cast<const EcdsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher =
      NewEcdsaPrehashBoringSsl(private_key->GetPublicKey());
  ASSERT_THAT(prehasher, IsOk());

  EXPECT_THAT((*prehasher)->Compute("different_message"),
              IsOkAndHolds(Ne(*test_vector.prehash)));
}

TEST(EcdsaPrehashBoringSslSingleTest, FipsModeWithoutBoringCryptoFails) {
  if (!IsFipsModeEnabled() || IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  const SignatureTestVector& test_vector = GetEcdsaTestVector(
      EcdsaParameters::CurveType::kNistP256, EcdsaParameters::HashType::kSha256,
      EcdsaParameters::SignatureEncoding::kDer,
      EcdsaParameters::Variant::kNoPrefix);
  const auto* private_key = dynamic_cast<const EcdsaPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());

  EXPECT_THAT(NewEcdsaPrehashBoringSsl(private_key->GetPublicKey()).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
