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

#include "tink/prf/internal/hkdf_prf_key_creator.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/prf/internal/hkdf_prf_test_vectors.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::TestParamInfo;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

struct TestCase {
  std::string name;
  const HkdfPrfKey& expected_key;
};

using HkdfPrfKeyCreatorParameterizedTest = TestWithParam<TestCase>;

TEST_P(HkdfPrfKeyCreatorParameterizedTest, CreateKeyWorks) {
  const HkdfPrfKey& expected_key = GetParam().expected_key;

  absl::StatusOr<std::unique_ptr<Key>> key =
      CreateHkdfPrfKey(expected_key.GetParameters(), std::nullopt);
  ASSERT_THAT(key, IsOk());

  const auto* hkdf_prf_key = dynamic_cast<const HkdfPrfKey*>(key->get());
  ASSERT_NE(hkdf_prf_key, nullptr);
  EXPECT_THAT(hkdf_prf_key->GetIdRequirement(), Eq(std::nullopt));
  EXPECT_THAT(hkdf_prf_key->GetParameters(), Eq(expected_key.GetParameters()));
}

TEST_P(HkdfPrfKeyCreatorParameterizedTest, CreateKeyTwiceYieldsDifferentKeys) {
  const HkdfPrfKey& expected_key = GetParam().expected_key;

  absl::StatusOr<std::unique_ptr<Key>> key1 =
      CreateHkdfPrfKey(expected_key.GetParameters(), std::nullopt);
  ASSERT_THAT(key1, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> key2 =
      CreateHkdfPrfKey(expected_key.GetParameters(), std::nullopt);
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(**key1, **key2);
}

TEST_P(HkdfPrfKeyCreatorParameterizedTest,
       CreateKeyWithKeyGenConfigurationWorks) {
  const HkdfPrfKey& expected_key = GetParam().expected_key;
  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddKeyCreator<HkdfPrfParameters>(
                  CreateHkdfPrfKey, key_creator_config),
              IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key = KeyGenConfigurationImpl::CreateKey(
      expected_key.GetParameters(), std::nullopt, key_creator_config);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetParameters(), Eq(expected_key.GetParameters()));
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(std::nullopt));
}

INSTANTIATE_TEST_SUITE_P(HkdfPrfKeyCreatorParameterizedTests,
                         HkdfPrfKeyCreatorParameterizedTest,
                         ValuesIn<TestCase>({
                             {/*name=*/"HkdfPrf22Sha1NoSalt",
                              /*expected_key=*/GetHkdfPrfTestVector(
                                  22, HkdfPrfParameters::HashType::kSha1)
                                  .key},
                             {/*name=*/"HkdfPrf22Sha256Salt",
                              /*expected_key=*/GetHkdfPrfTestVector(
                                  22, HkdfPrfParameters::HashType::kSha256)
                                  .key},
                             {/*name=*/"HkdfPrf80Sha1Salt",
                              /*expected_key=*/GetHkdfPrfTestVector(
                                  80, HkdfPrfParameters::HashType::kSha1)
                                  .key},
                             {/*name=*/"HkdfPrf80Sha256Salt",
                              /*expected_key=*/GetHkdfPrfTestVector(
                                  80, HkdfPrfParameters::HashType::kSha256)
                                  .key},
                         }),
                         [](const TestParamInfo<TestCase>& info) {
                           return info.param.name;
                         });

TEST(HkdfPrfKeyCreatorTest, CreateKeyWithIdRequirementFails) {
  const HkdfPrfParameters& params =
      GetHkdfPrfTestVector(22, HkdfPrfParameters::HashType::kSha256)
          .key.GetParameters();
  EXPECT_THAT(CreateHkdfPrfKey(params, 123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
