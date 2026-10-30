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

#include "tink/prf/subtle/create_aes_cmac_prf.h"

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
#include "tink/prf/internal/aes_cmac_prf_test_vectors.h"
#include "tink/prf/prf_set.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::Not;

using CreateAesCmacPrfTest =
    testing::TestWithParam<internal::AesCmacPrfTestVector>;

TEST_P(CreateAesCmacPrfTest, ComputePrfWithTestVectors) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const internal::AesCmacPrfTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<Prf>> prf = CreateAesCmacPrf(test_vector.key);
  ASSERT_THAT(prf, IsOk());

  EXPECT_THAT((*prf)->Compute(test_vector.message, test_vector.output.size()),
              IsOkAndHolds(test_vector.output));
  for (size_t length = 0; length < test_vector.output.size(); ++length) {
    EXPECT_THAT(
        (*prf)->Compute(test_vector.message, length),
        IsOkAndHolds(absl::string_view(test_vector.output).substr(0, length)));
  }
  EXPECT_THAT((*prf)->Compute(test_vector.message, 17), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    CreateAesCmacPrfTests, CreateAesCmacPrfTest,
    testing::ValuesIn(internal::CreateAesCmacPrfTestVectors()));

TEST(CreateAesCmacPrfFipsTest, FipsMode) {
  if (!internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }
  const internal::AesCmacPrfTestVector& test_vector =
      internal::GetAesCmacPrfTestVector(/*key_size_in_bytes=*/32);
  EXPECT_THAT(CreateAesCmacPrf(test_vector.key),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
