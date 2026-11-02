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

#include "tink/signature/subtle/create_slh_dsa_verifier.h"

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
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/internal/testing/slh_dsa_test_vectors.h"
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/signature/slh_dsa_private_key.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::CreateSlhDsaTestVectors;
using ::crypto::tink::internal::GetSlhDsaTestVector;
using ::crypto::tink::internal::SignatureTestVector;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

class CreateSlhDsaPublicKeyVerifyTestVectorTest
    : public TestWithParam<SignatureTestVector> {
 protected:
  void SetUp() override {
    if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
      GTEST_SKIP()
          << "kRequiresBoringCrypto is set but BoringCrypto is unavailable.";
    }
  }
};

TEST_P(CreateSlhDsaPublicKeyVerifyTestVectorTest, VerifyTestVectors) {
  const SignatureTestVector& test_vector = GetParam();
  const SlhDsaPrivateKey& private_key =
      dynamic_cast<const SlhDsaPrivateKey&>(*test_vector.signature_private_key);
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateSlhDsaPublicKeyVerify(private_key.GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(test_vector.signature, test_vector.message),
              IsOk());
}

INSTANTIATE_TEST_SUITE_P(CreateSlhDsaPublicKeyVerifyTestVectorTests,
                         CreateSlhDsaPublicKeyVerifyTestVectorTest,
                         ValuesIn(CreateSlhDsaTestVectors()));

TEST(CreateSlhDsaPublicKeyVerifyTest,
     VerifyFailsWithModifiedSignatureOrMessage) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "kRequiresBoringCrypto is set but BoringCrypto is unavailable.";
  }

  const SignatureTestVector& test_vector =
      GetSlhDsaTestVector(SlhDsaParameters::HashType::kSha2,
                          SlhDsaParameters::SignatureType::kSmallSignature,
                          SlhDsaParameters::Variant::kTink);
  const SlhDsaPrivateKey& private_key =
      dynamic_cast<const SlhDsaPrivateKey&>(*test_vector.signature_private_key);
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateSlhDsaPublicKeyVerify(private_key.GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  std::string modified_prefix = test_vector.signature;
  modified_prefix[0] ^= 0x01;
  EXPECT_THAT((*verifier)->Verify(modified_prefix, test_vector.message),
              StatusIs(absl::StatusCode::kInvalidArgument));

  std::string modified_signature = test_vector.signature;
  modified_signature[10] ^= 0x01;
  EXPECT_THAT((*verifier)->Verify(modified_signature, test_vector.message),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT((*verifier)->Verify(test_vector.signature, "modified message"),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(
      (*verifier)->Verify(absl::string_view(test_vector.signature)
                              .substr(0, test_vector.signature.size() - 1),
                          test_vector.message),
      StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT((*verifier)->Verify(absl::StrCat(test_vector.signature, "a"),
                                  test_vector.message),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
