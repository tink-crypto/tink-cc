// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/prf/hkdf_prf_parameters.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsFalse;
using ::testing::TestWithParam;
using ::testing::Values;

constexpr absl::string_view kSalt = "2023af";

struct TestCase {
  int key_size;
  HkdfPrfParameters::HashType hash_type;
};

using HkdfPrfParametersTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    HkdfPrfParametersCreateTestSuite, HkdfPrfParametersTest,
    Values(TestCase{/*key_size=*/16, HkdfPrfParameters::HashType::kSha1},
           TestCase{/*key_size=*/16, HkdfPrfParameters::HashType::kSha224},
           TestCase{/*key_size=*/16, HkdfPrfParameters::HashType::kSha256},
           TestCase{/*key_size=*/16, HkdfPrfParameters::HashType::kSha384},
           TestCase{/*key_size=*/32, HkdfPrfParameters::HashType::kSha512}));

TEST_P(HkdfPrfParametersTest, Create) {
  TestCase test_case = GetParam();
  std::string salt = test::HexDecodeOrDie(kSalt);

  util::StatusOr<HkdfPrfParameters> parameters =
      HkdfPrfParameters::Create(test_case.key_size, test_case.hash_type, salt);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->KeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(parameters->GetHashType(), Eq(test_case.hash_type));
  EXPECT_THAT(parameters->GetSalt(), Eq(salt));
  EXPECT_THAT(parameters->HasIdRequirement(), IsFalse());
}

TEST(HkdfPrfParametersTest, CreateWithoutSaltWorks) {
  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/16, HkdfPrfParameters::HashType::kSha256,
      /*salt=*/absl::nullopt);
  ;
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->KeySizeInBytes(), Eq(16));
  EXPECT_THAT(parameters->GetHashType(),
              Eq(HkdfPrfParameters::HashType::kSha256));
  EXPECT_THAT(parameters->GetSalt(), Eq(absl::nullopt));
  EXPECT_THAT(parameters->HasIdRequirement(), IsFalse());
}

TEST(HkdfPrfParametersTest, CreateWithEmptySaltDefaultsToNullopt) {
  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/16, HkdfPrfParameters::HashType::kSha256,
      /*salt=*/"");
  ;
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->KeySizeInBytes(), Eq(16));
  EXPECT_THAT(parameters->GetHashType(),
              Eq(HkdfPrfParameters::HashType::kSha256));
  EXPECT_THAT(parameters->GetSalt(), Eq(absl::nullopt));
  EXPECT_THAT(parameters->HasIdRequirement(), IsFalse());
}

TEST(HkdfPrfParametersTest, CreateWithInvalidKeySizeFails) {
  EXPECT_THAT(HkdfPrfParameters::Create(/*key_size_in_bytes=*/15,
                                        HkdfPrfParameters::HashType::kSha256,
                                        /*salt=*/absl::nullopt)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Key size must be at least 16 bytes")));
}

TEST(HkdfPrfParametersTest, CreateWithInvalidKHashTypeFails) {
  EXPECT_THAT(
      HkdfPrfParameters::Create(
          /*key_size_in_bytes=*/16,
          HkdfPrfParameters::HashType::
              kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements,
          /*salt=*/absl::nullopt)
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Cannot create HkdfPrf parameters with unknown HashType")));
}

TEST(HkdfPrfParametersTest, CopyConstructor) {
  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/16, HkdfPrfParameters::HashType::kSha256,
      /*salt=*/absl::nullopt);
  ASSERT_THAT(parameters, IsOk());

  HkdfPrfParameters copy(*parameters);

  EXPECT_THAT(copy.KeySizeInBytes(), Eq(parameters->KeySizeInBytes()));
  EXPECT_THAT(copy.GetHashType(), Eq(parameters->GetHashType()));
  EXPECT_THAT(copy.HasIdRequirement(), IsFalse());
}

TEST(HkdfPrfParametersTest, CopyAssignment) {
  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/16, HkdfPrfParameters::HashType::kSha256,
      /*salt=*/absl::nullopt);
  ASSERT_THAT(parameters, IsOk());

  HkdfPrfParameters copy = *parameters;

  EXPECT_THAT(copy.KeySizeInBytes(), Eq(parameters->KeySizeInBytes()));
  EXPECT_THAT(copy.GetHashType(), Eq(parameters->GetHashType()));
  EXPECT_THAT(copy.HasIdRequirement(), IsFalse());
}

TEST_P(HkdfPrfParametersTest, ParametersEquals) {
  TestCase test_case = GetParam();
  std::string salt = test::HexDecodeOrDie(kSalt);

  util::StatusOr<HkdfPrfParameters> parameters =
      HkdfPrfParameters::Create(test_case.key_size, test_case.hash_type, salt);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HkdfPrfParameters> other_parameters =
      HkdfPrfParameters::Create(test_case.key_size, test_case.hash_type, salt);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(HkdfPrfParametersTest, DifferentKeySizeNotEqual) {
  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/16, HkdfPrfParameters::HashType::kSha256,
      /*salt=*/absl::nullopt);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HkdfPrfParameters> other_parameters =
      HkdfPrfParameters::Create(/*key_size_in_bytes=*/32,
                                HkdfPrfParameters::HashType::kSha256,
                                /*salt=*/absl::nullopt);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(HkdfPrfParametersTest, DifferentashTypeNotEqual) {
  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/16, HkdfPrfParameters::HashType::kSha256,
      /*salt=*/absl::nullopt);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HkdfPrfParameters> other_parameters =
      HkdfPrfParameters::Create(/*key_size_in_bytes=*/16,
                                HkdfPrfParameters::HashType::kSha512,
                                /*salt=*/absl::nullopt);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(HkdfPrfParametersTest, DifferentSaltNotEqual) {
  std::string salt1 = test::HexDecodeOrDie("2023ab");
  util::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/16, HkdfPrfParameters::HashType::kSha256,
      /*salt=*/salt1);
  ASSERT_THAT(parameters, IsOk());

  std::string salt2 = test::HexDecodeOrDie("2023af");
  util::StatusOr<HkdfPrfParameters> other_parameters =
      HkdfPrfParameters::Create(/*key_size_in_bytes=*/16,
                                HkdfPrfParameters::HashType::kSha256,
                                /*salt=*/salt2);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
