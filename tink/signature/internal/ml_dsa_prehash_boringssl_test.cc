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
///////////////////////////////////////////////////////////////////////////////

#include "tink/signature/internal/ml_dsa_prehash_boringssl.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "openssl/mldsa.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/signature/internal/ml_dsa_key_creator.h"
#include "tink/signature/internal/testing/ml_dsa_mu_test_vectors.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/prehash.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::TestWithParam;
using ::testing::Values;
using ::testing::ValuesIn;

struct TestCase {
  MlDsaParameters::Instance instance;
  MlDsaParameters::Variant variant;
  std::optional<int> id_requirement;
  std::string expected_prehash_prefix;
};

class MlDsaPrehashBoringSslTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
      GTEST_SKIP()
          << "kRequiresBoringCrypto is set but BoringCrypto is unavailable.";
    }
  }
};

INSTANTIATE_TEST_SUITE_P(
    MlDsaPrehashBoringSslTestSuite, MlDsaPrehashBoringSslTest,
    Values(TestCase{MlDsaParameters::Instance::kMlDsa44,
                    MlDsaParameters::Variant::kNoPrefixWithPrehashId,
                    0x02030405, std::string("\xff\x02\x03\x04\x05", 5)},
           TestCase{MlDsaParameters::Instance::kMlDsa65,
                    MlDsaParameters::Variant::kNoPrefixWithPrehashId,
                    0x02030405, std::string("\xff\x02\x03\x04\x05", 5)},
           TestCase{MlDsaParameters::Instance::kMlDsa87,
                    MlDsaParameters::Variant::kNoPrefixWithPrehashId,
                    0x02030405, std::string("\xff\x02\x03\x04\x05", 5)}));

TEST_P(MlDsaPrehashBoringSslTest, PrehashOutputLengthAndPrefixAreCorrect) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher =
      NewMlDsaPrehashBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(prehasher, IsOk());

  std::string message = "message to be prehashed";
  absl::StatusOr<std::string> prehash = (*prehasher)->Compute(message);
  ASSERT_THAT(prehash, IsOk());

  EXPECT_EQ((*prehash).size(),
            test_case.expected_prehash_prefix.size() + MLDSA_MU_BYTES);
  EXPECT_EQ(test_case.expected_prehash_prefix,
            (*prehash).substr(0, test_case.expected_prehash_prefix.size()));
}

TEST_P(MlDsaPrehashBoringSslTest, PrehashIsDeterministic) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher1 =
      NewMlDsaPrehashBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(prehasher1, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher2 =
      NewMlDsaPrehashBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(prehasher2, IsOk());

  std::string message = "message to be prehashed";
  absl::StatusOr<std::string> prehash1 = (*prehasher1)->Compute(message);
  ASSERT_THAT(prehash1, IsOk());

  absl::StatusOr<std::string> prehash2 = (*prehasher2)->Compute(message);
  ASSERT_THAT(prehash2, IsOk());

  EXPECT_EQ(*prehash1, *prehash2);
}

TEST_P(MlDsaPrehashBoringSslTest, DifferentMessagesProduceDifferentPrehashes) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher =
      NewMlDsaPrehashBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(prehasher, IsOk());

  absl::StatusOr<std::string> prehash1 = (*prehasher)->Compute("message1");
  ASSERT_THAT(prehash1, IsOk());

  absl::StatusOr<std::string> prehash2 = (*prehasher)->Compute("message2");
  ASSERT_THAT(prehash2, IsOk());

  EXPECT_NE(*prehash1, *prehash2);
}

TEST(MlDsaPrehashBoringSslNonParamTest, AcceptsVariants) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "kRequiresBoringCrypto is set but BoringCrypto is unavailable.";
  }
  // Test kTink is accepted
  auto tink_params = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());
  auto tink_key = CreateMlDsaKey(*tink_params, 0x01020304);
  ASSERT_THAT(tink_key, IsOk());
  EXPECT_THAT(NewMlDsaPrehashBoringSsl((*tink_key)->GetPublicKey()).status(),
              IsOk());

  // Test kNoPrefix is accepted
  auto noprefix_params = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(noprefix_params, IsOk());
  auto noprefix_key = CreateMlDsaKey(*noprefix_params, std::nullopt);
  ASSERT_THAT(noprefix_key, IsOk());
  EXPECT_THAT(
      NewMlDsaPrehashBoringSsl((*noprefix_key)->GetPublicKey()).status(),
      IsOk());
}

using MlDsaPrehashTest = TestWithParam<MlDsaMuTestVector>;

INSTANTIATE_TEST_SUITE_P(MlDsaPrehashTestSuite, MlDsaPrehashTest,
                         ValuesIn(CreateMlDsaMuTestVectors()));

TEST_P(MlDsaPrehashTest, PrehashMatchesExpected) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  MlDsaMuTestVector test_case = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters = MlDsaParameters::Create(
      test_case.instance, MlDsaParameters::Variant::kNoPrefixWithPrehashId);
  ASSERT_THAT(key_parameters, IsOk());

  constexpr uint32_t kKeyId = 0x01020304;
  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*key_parameters, test_case.public_key_bytes,
                             kKeyId, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher =
      NewMlDsaPrehashBoringSsl(*public_key);
  ASSERT_THAT(prehasher, IsOk());

  absl::StatusOr<std::string> prehash =
      (*prehasher)->Compute(test_case.message);
  ASSERT_THAT(prehash, IsOk());

  std::string expected_prefix("\xff\x01\x02\x03\x04", 5);
  EXPECT_EQ((*prehash).size(), 5 + MLDSA_MU_BYTES);
  EXPECT_EQ((*prehash).substr(0, 5), expected_prefix);
  EXPECT_EQ((*prehash).substr(5), test_case.mu);
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
