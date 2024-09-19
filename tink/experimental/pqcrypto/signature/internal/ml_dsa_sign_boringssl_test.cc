// Copyright 2024 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

#include "tink/experimental/pqcrypto/signature/internal/ml_dsa_sign_boringssl.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "openssl/mldsa.h"
#include "tink/experimental/pqcrypto/signature/internal/key_creators.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_parameters.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_private_key.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  MlDsaParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using MlDsaSignBoringSslTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    MlDsaSignBoringSslTestSuite, MlDsaSignBoringSslTest,
    Values(TestCase{MlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{MlDsaParameters::Variant::kNoPrefix, absl::nullopt, ""}));

TEST_P(MlDsaSignBoringSslTest, SignatureLengthIsCorrect) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  TestCase test_case = GetParam();

  util::StatusOr<MlDsaParameters> key_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignBoringSsl(**private_key);
  ASSERT_THAT(signer, IsOk());

  std::string message = "message to be signed";
  util::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  EXPECT_NE(*signature, message);
  EXPECT_EQ((*signature).size(),
            test_case.output_prefix.size() + MLDSA65_SIGNATURE_BYTES);
  EXPECT_EQ(test_case.output_prefix,
            (*signature).substr(0, test_case.output_prefix.size()));
}

TEST(MlDsaSignBoringSslTest, SignatureIsNonDeterministic) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  util::StatusOr<MlDsaParameters> key_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignBoringSsl(**private_key);
  ASSERT_THAT(signer, IsOk());

  // Sign the same message twice, using the same private key.
  std::string message = "message to be signed";
  util::StatusOr<std::string> first_signature = (*signer)->Sign(message);
  ASSERT_THAT(first_signature, IsOk());

  util::StatusOr<std::string> second_signature = (*signer)->Sign(message);
  ASSERT_THAT(second_signature, IsOk());

  // Check the signatures' sizes.
  EXPECT_EQ((*first_signature).size(), MLDSA65_SIGNATURE_BYTES);
  EXPECT_EQ((*second_signature).size(), MLDSA65_SIGNATURE_BYTES);

  EXPECT_NE(*first_signature, *second_signature);
}

TEST(MlDsaSignBoringSslTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  util::StatusOr<MlDsaParameters> key_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  EXPECT_THAT(NewMlDsaSignBoringSsl(**private_key).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
