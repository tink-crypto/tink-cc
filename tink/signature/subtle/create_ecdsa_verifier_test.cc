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

#include "tink/signature/subtle/create_ecdsa_verifier.h"

#include <cstddef>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::CreateEcdsaTestVectors;
using ::crypto::tink::internal::SignatureTestVector;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

class CreateEcdsaPublicKeyVerifyTestVectorTest
    : public TestWithParam<SignatureTestVector> {
 protected:
  void SetUp() override {
    if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
      GTEST_SKIP()
          << "kRequiresBoringCrypto is set but BoringCrypto is unavailable.";
    }
  }
};

TEST_P(CreateEcdsaPublicKeyVerifyTestVectorTest, VerifyTestVectors) {
  const SignatureTestVector& test_vector = GetParam();
  const EcdsaPrivateKey& private_key =
      dynamic_cast<const EcdsaPrivateKey&>(*test_vector.signature_private_key);
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateEcdsaPublicKeyVerify(private_key.GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(test_vector.signature, test_vector.message),
              IsOk());
}

TEST_P(CreateEcdsaPublicKeyVerifyTestVectorTest,
       VerifyFailsWithModifiedSignature) {
  const SignatureTestVector& test_vector = GetParam();
  const EcdsaPrivateKey& private_key =
      dynamic_cast<const EcdsaPrivateKey&>(*test_vector.signature_private_key);
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateEcdsaPublicKeyVerify(private_key.GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  for (size_t i = 0; i < test_vector.signature.size(); ++i) {
    std::string modified_signature = test_vector.signature;
    modified_signature[i] ^= 0x01;
    EXPECT_THAT((*verifier)->Verify(modified_signature, test_vector.message),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST_P(CreateEcdsaPublicKeyVerifyTestVectorTest,
       VerifyFailsWithModifiedMessage) {
  const SignatureTestVector& test_vector = GetParam();
  const EcdsaPrivateKey& private_key =
      dynamic_cast<const EcdsaPrivateKey&>(*test_vector.signature_private_key);
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateEcdsaPublicKeyVerify(private_key.GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(test_vector.signature,
                                  absl::StrCat(test_vector.message, "a")),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(CreateEcdsaPublicKeyVerifyTestVectorTest,
       VerifyFailsWithTruncatedSignature) {
  const SignatureTestVector& test_vector = GetParam();
  const EcdsaPrivateKey& private_key =
      dynamic_cast<const EcdsaPrivateKey&>(*test_vector.signature_private_key);
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateEcdsaPublicKeyVerify(private_key.GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  for (size_t len = 0; len < test_vector.signature.size(); ++len) {
    EXPECT_THAT((*verifier)->Verify(
                    absl::string_view(test_vector.signature).substr(0, len),
                    test_vector.message),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

INSTANTIATE_TEST_SUITE_P(CreateEcdsaPublicKeyVerifyTestVectorTests,
                         CreateEcdsaPublicKeyVerifyTestVectorTest,
                         ValuesIn(CreateEcdsaTestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
