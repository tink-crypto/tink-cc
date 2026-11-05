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

#include "tink/mac/subtle/create_hmac_chunked_mac.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/chunked_mac.h"
#include "tink/internal/fips_utils.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/mac/internal/hmac_test_vectors.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::crypto::tink::internal::CreateHmacTestVectors;
using ::crypto::tink::internal::GetHmacTestVector;
using ::crypto::tink::internal::HmacTestVector;
using ::crypto::tink::internal::IsFipsEnabledInSsl;
using ::crypto::tink::internal::IsFipsModeEnabled;
using ::testing::Eq;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using CreateHmacChunkedMacTestVectorsTest = TestWithParam<HmacTestVector>;

TEST_P(CreateHmacChunkedMacTestVectorsTest, ComputeMac) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  const HmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<ChunkedMac>> mac =
      CreateHmacChunkedMac(test_vector.key);
  ASSERT_THAT(mac, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMacComputation>> computation =
      (*mac)->CreateComputation();
  ASSERT_THAT(computation, IsOk());
  ASSERT_THAT((*computation)->Update(test_vector.message), IsOk());
  EXPECT_THAT((*computation)->ComputeMac(), IsOkAndHolds(Eq(test_vector.tag)));
}

TEST_P(CreateHmacChunkedMacTestVectorsTest, VerifyMac) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  const HmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<ChunkedMac>> mac =
      CreateHmacChunkedMac(test_vector.key);
  ASSERT_THAT(mac, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*mac)->CreateVerification(test_vector.tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update(test_vector.message), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), IsOk());
}

TEST_P(CreateHmacChunkedMacTestVectorsTest, ComputeAndVerifyMacMultipleChunks) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  const HmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<ChunkedMac>> mac =
      CreateHmacChunkedMac(test_vector.key);
  ASSERT_THAT(mac, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMacComputation>> computation =
      (*mac)->CreateComputation();
  ASSERT_THAT(computation, IsOk());
  absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*mac)->CreateVerification(test_vector.tag);
  ASSERT_THAT(verification, IsOk());
  for (char c : test_vector.message) {
    std::string chunk(1, c);
    ASSERT_THAT((*computation)->Update(chunk), IsOk());
    ASSERT_THAT((*verification)->Update(chunk), IsOk());
  }
  EXPECT_THAT((*computation)->ComputeMac(), IsOkAndHolds(Eq(test_vector.tag)));
  EXPECT_THAT((*verification)->VerifyMac(), IsOk());
}

TEST_P(CreateHmacChunkedMacTestVectorsTest, VerifyMacFailsWithModifiedMessage) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  const HmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<ChunkedMac>> mac =
      CreateHmacChunkedMac(test_vector.key);
  ASSERT_THAT(mac, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*mac)->CreateVerification(test_vector.tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update(test_vector.message), IsOk());
  ASSERT_THAT((*verification)->Update("x"), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), Not(IsOk()));
}

TEST_P(CreateHmacChunkedMacTestVectorsTest, VerifyMacFailsWithModifiedTag) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  const HmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<ChunkedMac>> mac =
      CreateHmacChunkedMac(test_vector.key);
  ASSERT_THAT(mac, IsOk());

  std::string modified_tag = test_vector.tag;
  modified_tag.back() ^= 1;
  absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*mac)->CreateVerification(modified_tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update(test_vector.message), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), Not(IsOk()));
}

TEST_P(CreateHmacChunkedMacTestVectorsTest, VerifyMacFailsWithTruncatedTag) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  const HmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<ChunkedMac>> mac =
      CreateHmacChunkedMac(test_vector.key);
  ASSERT_THAT(mac, IsOk());

  std::string truncated_tag = test_vector.tag;
  truncated_tag.pop_back();
  absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*mac)->CreateVerification(truncated_tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update(test_vector.message), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(CreateHmacChunkedMacTestVectorsTest,
                         CreateHmacChunkedMacTestVectorsTest,
                         ValuesIn(CreateHmacTestVectors()));

TEST(CreateHmacChunkedMacTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test only run in FIPS-only mode";
  }
  const HmacTestVector& test_vector = GetHmacTestVector(
      /*key_size_in_bytes=*/16, HmacParameters::HashType::kSha256,
      HmacParameters::Variant::kTink);
  if (IsFipsEnabledInSsl()) {
    EXPECT_THAT(CreateHmacChunkedMac(test_vector.key), IsOk());
  } else {
    EXPECT_THAT(CreateHmacChunkedMac(test_vector.key), Not(IsOk()));
  }
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
