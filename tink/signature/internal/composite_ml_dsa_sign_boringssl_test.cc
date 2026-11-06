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

#include "tink/signature/internal/composite_ml_dsa_sign_boringssl.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/signature/composite_ml_dsa_private_key.h"
#include "tink/signature/internal/testing/composite_ml_dsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::StartsWith;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using CompositeMlDsaSignBoringSslTest = TestWithParam<SignatureTestVector>;

TEST_P(CompositeMlDsaSignBoringSslTest, SignatureOutputPrefixIsCorrect) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  const SignatureTestVector& test_vector = GetParam();
  const CompositeMlDsaPrivateKey& private_key =
      dynamic_cast<const CompositeMlDsaPrivateKey&>(
          *test_vector.signature_private_key);

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewCompositeMlDsaSign(private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::string> signature = (*signer)->Sign(test_vector.message);
  ASSERT_THAT(signature, IsOk());

  EXPECT_THAT(*signature, StartsWith(private_key.GetOutputPrefix()));
}

TEST_P(CompositeMlDsaSignBoringSslTest, SignatureIsNonDeterministic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  const SignatureTestVector& test_vector = GetParam();
  const CompositeMlDsaPrivateKey& private_key =
      dynamic_cast<const CompositeMlDsaPrivateKey&>(
          *test_vector.signature_private_key);

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewCompositeMlDsaSign(private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::string> first_signature =
      (*signer)->Sign(test_vector.message);
  ASSERT_THAT(first_signature, IsOk());
  absl::StatusOr<std::string> second_signature =
      (*signer)->Sign(test_vector.message);
  ASSERT_THAT(second_signature, IsOk());

  EXPECT_NE(*first_signature, *second_signature);
}

TEST_P(CompositeMlDsaSignBoringSslTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is true.";
  }

  const SignatureTestVector& test_vector = GetParam();
  const CompositeMlDsaPrivateKey& private_key =
      dynamic_cast<const CompositeMlDsaPrivateKey&>(
          *test_vector.signature_private_key);

  // Check that creating the signer fails in FIPS mode.
  EXPECT_THAT(NewCompositeMlDsaSign(private_key).status(),
              StatusIs(absl::StatusCode::kInternal));
}

INSTANTIATE_TEST_SUITE_P(CompositeMlDsaSignTestSuite,
                         CompositeMlDsaSignBoringSslTest,
                         ValuesIn(CreateCompositeMlDsaTestVectors()));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
