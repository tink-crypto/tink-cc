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

#include "tink/prf/subtle/create_hmac_prf.h"

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
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/prf/internal/hmac_prf_test_vectors.h"
#include "tink/prf/prf_set.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::Not;

using CreateHmacPrfTest = testing::TestWithParam<internal::HmacPrfTestVector>;

TEST_P(CreateHmacPrfTest, ComputePrfWithTestVectors) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Not supported if FIPS-only mode is enabled and BoringCrypto is not "
           "available";
  }
  const internal::HmacPrfTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<Prf>> prf = CreateHmacPrf(test_vector.key);
  ASSERT_THAT(prf, IsOk());

  EXPECT_THAT((*prf)->Compute(test_vector.message, test_vector.output.size()),
              IsOkAndHolds(test_vector.output));
  for (size_t length = 0; length < test_vector.output.size(); ++length) {
    EXPECT_THAT(
        (*prf)->Compute(test_vector.message, length),
        IsOkAndHolds(absl::string_view(test_vector.output).substr(0, length)));
  }
  // 65 bytes exceeds the maximum output length of all supported hash functions
  // (at most 64 bytes, for SHA-512).
  EXPECT_THAT((*prf)->Compute(test_vector.message, 65), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    CreateHmacPrfTests, CreateHmacPrfTest,
    testing::ValuesIn(internal::CreateHmacPrfTestVectors()));

TEST(CreateHmacPrfFipsTest, FipsModeWithoutBoringCryptoFails) {
  if (!internal::IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Only supported in FIPS-only mode without BoringCrypto available";
  }
  const internal::HmacPrfTestVector& test_vector =
      internal::GetHmacPrfTestVector(/*key_size_in_bytes=*/40,
                                     HmacPrfParameters::HashType::kSha256);
  EXPECT_THAT(CreateHmacPrf(test_vector.key),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
