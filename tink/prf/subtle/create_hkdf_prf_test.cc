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

#include "tink/prf/subtle/create_hkdf_prf.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/prf/internal/hkdf_prf_test_vectors.h"
#include "tink/prf/prf_set.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::HasSubstr;

using CreateHkdfPrfTest = testing::TestWithParam<internal::HkdfPrfTestVector>;

TEST_P(CreateHkdfPrfTest, ComputePrfWithTestVectors) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const internal::HkdfPrfTestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<Prf>> prf = CreateHkdfPrf(test_vector.key);
  ASSERT_THAT(prf, IsOk());

  EXPECT_THAT((*prf)->Compute(test_vector.input, test_vector.output.size()),
              IsOkAndHolds(test_vector.output));
  for (size_t length = 0; length < test_vector.output.size(); ++length) {
    EXPECT_THAT(
        (*prf)->Compute(test_vector.input, length),
        IsOkAndHolds(absl::string_view(test_vector.output).substr(0, length)));
  }
}

INSTANTIATE_TEST_SUITE_P(
    CreateHkdfPrfTests, CreateHkdfPrfTest,
    testing::ValuesIn(internal::CreateHkdfPrfTestVectors()));

TEST(CreateHkdfPrfSingleTest, UnsupportedHashTypeFails) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  for (HkdfPrfParameters::HashType hash_type :
       {HkdfPrfParameters::HashType::kSha224,
        HkdfPrfParameters::HashType::kSha384}) {
    absl::StatusOr<HkdfPrfParameters> parameters =
        HkdfPrfParameters::Create(/*key_size_in_bytes=*/32, hash_type,
                                  /*salt=*/std::nullopt);
    ASSERT_THAT(parameters, IsOk());
    absl::StatusOr<HkdfPrfKey> key = HkdfPrfKey::Create(
        *parameters, RestrictedData(32), GetPartialKeyAccess());
    ASSERT_THAT(key, IsOk());
    EXPECT_THAT(CreateHkdfPrf(*key),
                StatusIs(absl::StatusCode::kInvalidArgument,
                         HasSubstr("Unsupported hash type")));
  }
}

TEST(CreateHkdfPrfFipsTest, FipsMode) {
  if (!internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }
  const internal::HkdfPrfTestVector& test_vector =
      internal::GetHkdfPrfTestVector(/*key_size_in_bytes=*/22,
                                     HkdfPrfParameters::HashType::kSha256);
  EXPECT_THAT(CreateHkdfPrf(test_vector.key),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
