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

#include "tink/mac/internal/hmac_boringssl.h"

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
#include "tink/mac/hmac_key.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/mac/internal/hmac_test_vectors.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using HmacBoringSslTestVectorsTest = TestWithParam<HmacTestVector>;

TEST_P(HmacBoringSslTestVectorsTest, ComputeAndVerifyMac) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  const HmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<Mac>> mac = NewHmacBoringSsl(test_vector.key);
  ASSERT_THAT(mac, IsOk());

  EXPECT_THAT((*mac)->ComputeMac(test_vector.message),
              IsOkAndHolds(Eq(test_vector.tag)));
  EXPECT_THAT((*mac)->VerifyMac(test_vector.tag, test_vector.message), IsOk());
}

TEST_P(HmacBoringSslTestVectorsTest, VerifyModifiedOrTruncatedMacFails) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  const HmacTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<Mac>> mac = NewHmacBoringSsl(test_vector.key);
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

INSTANTIATE_TEST_SUITE_P(HmacBoringSslTestVectorsTests,
                         HmacBoringSslTestVectorsTest,
                         ValuesIn(CreateHmacTestVectors()));

TEST(HmacBoringSslTest, EmptyData) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test is skipped if kOnlyUseFips is set, but BoringCrypto "
                    "is not available.";
  }
  absl::StatusOr<HmacParameters> params = HmacParameters::Create(
      /*key_size_in_bytes=*/16, /*cryptographic_tag_size_in_bytes=*/16,
      HmacParameters::HashType::kSha256, HmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());
  absl::StatusOr<HmacKey> key =
      HmacKey::Create(*params, RestrictedData(16),
                      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Mac>> mac = NewHmacBoringSsl(*key);
  ASSERT_THAT(mac, IsOk());

  absl::StatusOr<std::string> tag = (*mac)->ComputeMac("");
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT((*mac)->VerifyMac(*tag, ""), IsOk());
  EXPECT_THAT((*mac)->VerifyMac(*tag, absl::string_view(nullptr, 0)), IsOk());

  absl::StatusOr<std::string> null_tag =
      (*mac)->ComputeMac(absl::string_view(nullptr, 0));
  ASSERT_THAT(null_tag, IsOkAndHolds(Eq(*tag)));
}

TEST(HmacBoringSslTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test only run in FIPS-only mode";
  }
  const HmacTestVector& test_vector = GetHmacTestVector(
      /*key_size_in_bytes=*/16, HmacParameters::HashType::kSha256,
      HmacParameters::Variant::kTink);
  if (IsFipsEnabledInSsl()) {
    EXPECT_THAT(NewHmacBoringSsl(test_vector.key), IsOk());
  } else {
    EXPECT_THAT(NewHmacBoringSsl(test_vector.key), Not(IsOk()));
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
