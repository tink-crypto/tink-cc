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

#include "tink/signature/subtle/create_ml_dsa_signer.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/testing/ml_dsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/subtle/create_ml_dsa_verifier.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::crypto::tink::internal::CreateMlDsaTestVectors;
using ::crypto::tink::internal::SignatureTestVector;
using ::testing::StartsWith;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

class CreateMlDsaPublicKeySignTestVectorTest
    : public TestWithParam<SignatureTestVector> {
 protected:
  void SetUp() override {
    if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
      GTEST_SKIP()
          << "kRequiresBoringCrypto is set but BoringCrypto is unavailable.";
    }
  }
};

TEST_P(CreateMlDsaPublicKeySignTestVectorTest, SignAndVerifyTestVectors) {
  const SignatureTestVector& test_vector = GetParam();
  const MlDsaPrivateKey& private_key =
      dynamic_cast<const MlDsaPrivateKey&>(*test_vector.signature_private_key);
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      CreateMlDsaPublicKeySign(private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::string> signature = (*signer)->Sign(test_vector.message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT(*signature, StartsWith(private_key.GetOutputPrefix()));
  EXPECT_EQ(signature->size(), test_vector.signature.size());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateMlDsaPublicKeyVerify(private_key.GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, test_vector.message), IsOk());
}

TEST_P(CreateMlDsaPublicKeySignTestVectorTest, SignIsNonDeterministic) {
  const SignatureTestVector& test_vector = GetParam();
  const MlDsaPrivateKey& private_key =
      dynamic_cast<const MlDsaPrivateKey&>(*test_vector.signature_private_key);
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      CreateMlDsaPublicKeySign(private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::string> first_signature =
      (*signer)->Sign(test_vector.message);
  ASSERT_THAT(first_signature, IsOk());

  absl::StatusOr<std::string> second_signature =
      (*signer)->Sign(test_vector.message);
  ASSERT_THAT(second_signature, IsOk());

  EXPECT_NE(*first_signature, *second_signature);
}

INSTANTIATE_TEST_SUITE_P(CreateMlDsaPublicKeySignTestVectorTests,
                         CreateMlDsaPublicKeySignTestVectorTest,
                         ValuesIn(CreateMlDsaTestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
