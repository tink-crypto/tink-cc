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

#include "tink/signature/internal/ml_dsa_chunked_prehash_boringssl.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "openssl/mldsa.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/signature/chunked_prehash.h"
#include "tink/signature/internal/ml_dsa_key_creator.h"
#include "tink/signature/internal/testing/ml_dsa_mu_test_vectors.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::TestWithParam;
using ::testing::Values;
using ::testing::ValuesIn;

struct TestCase {
  MlDsaParameters::Instance instance;
  MlDsaParameters::Variant variant;
  std::optional<int> id_requirement;
};

class MlDsaChunkedPrehashBoringSslTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
      GTEST_SKIP()
          << "kRequiresBoringCrypto is set but BoringCrypto is unavailable.";
    }
  }
};

INSTANTIATE_TEST_SUITE_P(
    MlDsaChunkedPrehashBoringSslTestSuite, MlDsaChunkedPrehashBoringSslTest,
    Values(TestCase{MlDsaParameters::Instance::kMlDsa44,
                    MlDsaParameters::Variant::kNoPrefixWithPrehashId,
                    0x02030405},
           TestCase{MlDsaParameters::Instance::kMlDsa65,
                    MlDsaParameters::Variant::kNoPrefixWithPrehashId,
                    0x02030405},
           TestCase{MlDsaParameters::Instance::kMlDsa87,
                    MlDsaParameters::Variant::kNoPrefixWithPrehashId,
                    0x02030405}));

TEST_P(MlDsaChunkedPrehashBoringSslTest,
       DifferentMessagesProduceDifferentPrehashes) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedPrehash>> prehasher =
      NewMlDsaChunkedPrehashBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(prehasher, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>> computation1 =
      (*prehasher)->CreateComputation();
  ASSERT_THAT(computation1, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>> computation2 =
      (*prehasher)->CreateComputation();
  ASSERT_THAT(computation2, IsOk());

  EXPECT_THAT((*computation1)->Update("message1"), IsOk());
  absl::StatusOr<std::string> prehash1 = (*computation1)->GetPrehash();
  ASSERT_THAT(prehash1, IsOk());

  EXPECT_THAT((*computation2)->Update("message2"), IsOk());
  absl::StatusOr<std::string> prehash2 = (*computation2)->GetPrehash();
  ASSERT_THAT(prehash2, IsOk());

  EXPECT_NE(*prehash1, *prehash2);
}

TEST_P(MlDsaChunkedPrehashBoringSslTest, UpdateAfterGetPrehashFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedPrehash>> prehasher =
      NewMlDsaChunkedPrehashBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(prehasher, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>> computation =
      (*prehasher)->CreateComputation();
  ASSERT_THAT(computation, IsOk());

  EXPECT_THAT((*computation)->Update("message to be prehashed"), IsOk());
  EXPECT_THAT((*computation)->GetPrehash(), IsOk());

  EXPECT_THAT((*computation)->Update("more data"),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_P(MlDsaChunkedPrehashBoringSslTest, GetPrehashTwiceFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedPrehash>> prehasher =
      NewMlDsaChunkedPrehashBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(prehasher, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>> computation =
      (*prehasher)->CreateComputation();
  ASSERT_THAT(computation, IsOk());

  EXPECT_THAT((*computation)->Update("message to be prehashed"), IsOk());
  EXPECT_THAT((*computation)->GetPrehash(), IsOk());

  EXPECT_THAT((*computation)->GetPrehash(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST(MlDsaChunkedPrehashBoringSslNonParamTest, AcceptsVariants) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "kRequiresBoringCrypto is set but BoringCrypto is unavailable.";
  }
  // Test kTink is accepted
  absl::StatusOr<MlDsaParameters> tink_params = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());
  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> tink_key =
      CreateMlDsaKey(*tink_params, 0x01020304);
  ASSERT_THAT(tink_key, IsOk());
  EXPECT_THAT(
      NewMlDsaChunkedPrehashBoringSsl((*tink_key)->GetPublicKey()).status(),
      IsOk());

  // Test kNoPrefix is accepted
  absl::StatusOr<MlDsaParameters> noprefix_params = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(noprefix_params, IsOk());
  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> noprefix_key =
      CreateMlDsaKey(*noprefix_params, std::nullopt);
  ASSERT_THAT(noprefix_key, IsOk());
  EXPECT_THAT(
      NewMlDsaChunkedPrehashBoringSsl((*noprefix_key)->GetPublicKey()).status(),
      IsOk());
}

using MlDsaChunkedPrehashTest = TestWithParam<MlDsaMuTestVector>;

INSTANTIATE_TEST_SUITE_P(MlDsaChunkedPrehashTestSuite, MlDsaChunkedPrehashTest,
                         ValuesIn(CreateMlDsaMuTestVectors()));

TEST_P(MlDsaChunkedPrehashTest, PrehashMatchesExpectedInOneChunk) {
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

  absl::StatusOr<std::unique_ptr<ChunkedPrehash>> prehasher =
      NewMlDsaChunkedPrehashBoringSsl(*public_key);
  ASSERT_THAT(prehasher, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>> computation =
      (*prehasher)->CreateComputation();
  ASSERT_THAT(computation, IsOk());
  EXPECT_THAT((*computation)->Update(test_case.message), IsOk());
  absl::StatusOr<std::string> prehash = (*computation)->GetPrehash();
  ASSERT_THAT(prehash, IsOk());

  std::string expected_prefix("\xff\x01\x02\x03\x04");
  EXPECT_EQ((*prehash).size(), 5 + MLDSA_MU_BYTES);
  EXPECT_EQ((*prehash).substr(0, 5), expected_prefix);
  EXPECT_EQ((*prehash).substr(5), test_case.mu);
}

TEST_P(MlDsaChunkedPrehashTest, PrehashMatchesExpectedInByteSizedChunks) {
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

  absl::StatusOr<std::unique_ptr<ChunkedPrehash>> prehasher =
      NewMlDsaChunkedPrehashBoringSsl(*public_key);
  ASSERT_THAT(prehasher, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>> computation =
      (*prehasher)->CreateComputation();
  ASSERT_THAT(computation, IsOk());
  for (char c : test_case.message) {
    EXPECT_THAT((*computation)->Update(absl::string_view(&c, 1)), IsOk());
  }
  absl::StatusOr<std::string> prehash = (*computation)->GetPrehash();
  ASSERT_THAT(prehash, IsOk());

  std::string expected_prefix("\xff\x01\x02\x03\x04");
  EXPECT_EQ((*prehash).size(), 5 + MLDSA_MU_BYTES);
  EXPECT_EQ((*prehash).substr(0, 5), expected_prefix);
  EXPECT_EQ((*prehash).substr(5), test_case.mu);
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
