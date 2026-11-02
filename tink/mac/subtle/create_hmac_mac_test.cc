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

#include "tink/mac/subtle/create_hmac_mac.h"

#include <cstddef>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/fips_utils.h"
#include "tink/mac.h"
#include "tink/mac/internal/hmac_test_vectors.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::CreateHmacTestVectors;
using ::crypto::tink::internal::HmacTestVector;
using ::crypto::tink::internal::IsFipsEnabledInSsl;
using ::crypto::tink::internal::IsFipsModeEnabled;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using CreateHmacMacTestVectorsTest = TestWithParam<HmacTestVector>;

TEST_P(CreateHmacMacTestVectorsTest, ComputeAndVerifyMac) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  const HmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<Mac>> mac = CreateHmacMac(test_vector.key);
  ASSERT_THAT(mac, IsOk());

  EXPECT_THAT((*mac)->ComputeMac(test_vector.message),
              IsOkAndHolds(Eq(test_vector.tag)));
  EXPECT_THAT((*mac)->VerifyMac(test_vector.tag, test_vector.message), IsOk());
}

TEST_P(CreateHmacMacTestVectorsTest, VerifyModifiedOrTruncatedMacFails) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  const HmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<Mac>> mac = CreateHmacMac(test_vector.key);
  ASSERT_THAT(mac, IsOk());

  for (size_t i = 0; i < test_vector.tag.size(); ++i) {
    std::string modified_tag = test_vector.tag;
    modified_tag[i] ^= 0x01;
    EXPECT_THAT((*mac)->VerifyMac(modified_tag, test_vector.message),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  for (size_t i = 0; i < test_vector.tag.size(); ++i) {
    EXPECT_THAT(
        (*mac)->VerifyMac(absl::string_view(test_vector.tag).substr(0, i),
                          test_vector.message),
        StatusIs(absl::StatusCode::kInvalidArgument));
  }
  std::string extended_tag = test_vector.tag + "x";
  EXPECT_THAT((*mac)->VerifyMac(extended_tag, test_vector.message),
              StatusIs(absl::StatusCode::kInvalidArgument));

  std::string modified_message = test_vector.message + "x";
  EXPECT_THAT((*mac)->VerifyMac(test_vector.tag, modified_message),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

INSTANTIATE_TEST_SUITE_P(CreateHmacMacTestVectorsTests,
                         CreateHmacMacTestVectorsTest,
                         ValuesIn(CreateHmacTestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
