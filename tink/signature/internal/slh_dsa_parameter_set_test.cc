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

#include "tink/signature/internal/slh_dsa_parameter_set.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;

struct TestCase {
  SlhDsaParameterSet parameter_set;
  SlhDsaParameters::HashType hash_type;
  int private_key_size_in_bytes;
  int public_key_size_in_bytes;
  SlhDsaParameters::SignatureType signature_type;
};

using SlhDsaParameterSetTest = ::testing::TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    SlhDsaParameterSetTestSuite, SlhDsaParameterSetTest,
    ::testing::Values(
        // SLH-DSA-SHA2-128s
        TestCase{SlhDsaParameterSet::Sha2_128s(),
                 SlhDsaParameters::HashType::kSha2, 64, 32,
                 SlhDsaParameters::SignatureType::kSmallSignature},
        // SLH-DSA-SHAKE-256f
        TestCase{SlhDsaParameterSet::Shake_256f(),
                 SlhDsaParameters::HashType::kShake, 128, 64,
                 SlhDsaParameters::SignatureType::kFastSigning}));

TEST_P(SlhDsaParameterSetTest, Getters) {
  const TestCase& test_case = GetParam();
  EXPECT_THAT(test_case.parameter_set.GetHashType(), Eq(test_case.hash_type));
  EXPECT_THAT(test_case.parameter_set.GetPrivateKeySizeInBytes(),
              Eq(test_case.private_key_size_in_bytes));
  EXPECT_THAT(test_case.parameter_set.GetPublicKeySizeInBytes(),
              Eq(test_case.public_key_size_in_bytes));
  EXPECT_THAT(test_case.parameter_set.GetSignatureType(),
              Eq(test_case.signature_type));
}

TEST_P(SlhDsaParameterSetTest, OperatorEquals) {
  const TestCase& test_case = GetParam();
  EXPECT_THAT(test_case.parameter_set == test_case.parameter_set, IsTrue());
}

TEST(SlhDsaParameterSetTest, OperatorNotEquals) {
  EXPECT_THAT(
      SlhDsaParameterSet::Sha2_128s() != SlhDsaParameterSet::Sha2_128s(),
      IsFalse());
  EXPECT_THAT(
      SlhDsaParameterSet::Shake_256f() != SlhDsaParameterSet::Shake_256f(),
      IsFalse());
  EXPECT_THAT(
      SlhDsaParameterSet::Sha2_128s() != SlhDsaParameterSet::Shake_256f(),
      IsTrue());
}

// We don't support other configurations for the moment.
TEST_P(SlhDsaParameterSetTest, GetSlhDsaParameterSet) {
  const TestCase& test_case = GetParam();
  if (test_case.hash_type != SlhDsaParameters::HashType::kSha2) {
    GTEST_SKIP() << "We don't support other configurations for the moment";
  }

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      test_case.hash_type, test_case.private_key_size_in_bytes,
      test_case.signature_type, SlhDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<SlhDsaParameterSet> parameter_set =
      GetSlhDsaParameterSet(*parameters);
  ASSERT_THAT(parameter_set, IsOk());
  EXPECT_THAT(*parameter_set == test_case.parameter_set, IsTrue());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
