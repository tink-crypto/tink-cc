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

#include "tink/mac/subtle/create_aes_cmac_mac.h"

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
#include "tink/mac/aes_cmac_key.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/mac/internal/aes_cmac_test_vectors.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"

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

using CreateAesCmacMacTestVectorsTest = TestWithParam<TinkAesCmacTestVector>;

TEST_P(CreateAesCmacMacTestVectorsTest, ComputeAndVerifyMac) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const TinkAesCmacTestVector& param = GetParam();

  absl::StatusOr<std::unique_ptr<Mac>> mac = CreateAesCmacMac(param.key);
  ASSERT_THAT(mac, IsOk());

  EXPECT_THAT((*mac)->ComputeMac(param.message), IsOkAndHolds(Eq(param.tag)));
  EXPECT_THAT((*mac)->VerifyMac(param.tag, param.message), IsOk());

  // Modify a byte in the tag (covers prefix and raw tag bytes).
  for (size_t i = 0; i < param.tag.size(); ++i) {
    std::string modified_tag = param.tag;
    modified_tag[i] ^= 1;
    EXPECT_THAT((*mac)->VerifyMac(modified_tag, param.message),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  // Truncate or extend the tag.
  for (size_t i = 0; i < param.tag.size(); ++i) {
    EXPECT_THAT((*mac)->VerifyMac(absl::string_view(param.tag).substr(0, i),
                                  param.message),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  std::string extended_tag = param.tag + "x";
  EXPECT_THAT((*mac)->VerifyMac(extended_tag, param.message),
              StatusIs(absl::StatusCode::kInvalidArgument));

  std::string modified_message = param.message + "x";
  EXPECT_THAT((*mac)->VerifyMac(param.tag, modified_message),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

INSTANTIATE_TEST_SUITE_P(CreateAesCmacMacTestVectorsTest,
                         CreateAesCmacMacTestVectorsTest,
                         ValuesIn(AesCmacTestVectors()),
                         [](const TestParamInfo<TinkAesCmacTestVector>& info) {
                           return info.param.test_name;
                         });

TEST(CreateAesCmacMacTest, EmptyData) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  absl::StatusOr<AesCmacParameters> params = AesCmacParameters::Create(
      /*key_size_in_bytes=*/16, /*cryptographic_tag_size_in_bytes=*/16,
      AesCmacParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());
  absl::StatusOr<AesCmacKey> key =
      AesCmacKey::Create(*params, RestrictedData(16),
                         /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Mac>> mac = CreateAesCmacMac(*key);
  ASSERT_THAT(mac, IsOk());

  absl::StatusOr<std::string> tag = (*mac)->ComputeMac("");
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT((*mac)->VerifyMac(*tag, ""), IsOk());
  EXPECT_THAT((*mac)->VerifyMac(*tag, absl::string_view(nullptr, 0)), IsOk());

  absl::StatusOr<std::string> null_tag =
      (*mac)->ComputeMac(absl::string_view(nullptr, 0));
  ASSERT_THAT(null_tag, IsOkAndHolds(Eq(*tag)));
}

TEST(CreateAesCmacMacTest, FailInFipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only test in FIPS-only mode";
  }
  const TinkAesCmacTestVector& param = AesCmacTestVectors()[0];
  EXPECT_THAT(CreateAesCmacMac(param.key), Not(IsOk()));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
