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

#include "tink/mac/subtle/create_aes_cmac_chunked_mac.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/chunked_mac.h"
#include "tink/internal/fips_utils.h"
#include "tink/mac/internal/aes_cmac_test_vectors.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::AesCmacTestVectors;
using ::crypto::tink::internal::IsFipsModeEnabled;
using ::crypto::tink::internal::TinkAesCmacTestVector;
using ::testing::Eq;
using ::testing::Not;
using ::testing::TestParamInfo;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using CreateAesCmacChunkedMacTestVectorsTest =
    TestWithParam<TinkAesCmacTestVector>;

TEST_P(CreateAesCmacChunkedMacTestVectorsTest, ComputeMac) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const TinkAesCmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<ChunkedMac>> mac =
      CreateAesCmacChunkedMac(test_vector.key);
  ASSERT_THAT(mac, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMacComputation>> computation =
      (*mac)->CreateComputation();
  ASSERT_THAT(computation, IsOk());
  ASSERT_THAT((*computation)->Update(test_vector.message), IsOk());
  EXPECT_THAT((*computation)->ComputeMac(), IsOkAndHolds(Eq(test_vector.tag)));
}

TEST_P(CreateAesCmacChunkedMacTestVectorsTest, VerifyMac) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const TinkAesCmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<ChunkedMac>> mac =
      CreateAesCmacChunkedMac(test_vector.key);
  ASSERT_THAT(mac, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*mac)->CreateVerification(test_vector.tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update(test_vector.message), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), IsOk());
}

TEST_P(CreateAesCmacChunkedMacTestVectorsTest,
       ComputeAndVerifyMacMultipleChunks) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const TinkAesCmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<ChunkedMac>> mac =
      CreateAesCmacChunkedMac(test_vector.key);
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

TEST_P(CreateAesCmacChunkedMacTestVectorsTest,
       VerifyMacFailsWithModifiedMessage) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const TinkAesCmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<ChunkedMac>> mac =
      CreateAesCmacChunkedMac(test_vector.key);
  ASSERT_THAT(mac, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*mac)->CreateVerification(test_vector.tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update(test_vector.message), IsOk());
  ASSERT_THAT((*verification)->Update("x"), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), Not(IsOk()));
}

TEST_P(CreateAesCmacChunkedMacTestVectorsTest, VerifyMacFailsWithModifiedTag) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const TinkAesCmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<ChunkedMac>> mac =
      CreateAesCmacChunkedMac(test_vector.key);
  ASSERT_THAT(mac, IsOk());

  std::string modified_tag = test_vector.tag;
  modified_tag.back() ^= 1;
  absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*mac)->CreateVerification(modified_tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update(test_vector.message), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(CreateAesCmacChunkedMacTestVectorsTest,
                         CreateAesCmacChunkedMacTestVectorsTest,
                         ValuesIn(AesCmacTestVectors()),
                         [](const TestParamInfo<TinkAesCmacTestVector>& info) {
                           return info.param.test_name;
                         });

TEST(CreateAesCmacChunkedMacTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test only for FIPS-only mode";
  }
  const TinkAesCmacTestVector& param = AesCmacTestVectors()[0];
  EXPECT_THAT(CreateAesCmacChunkedMac(param.key).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
