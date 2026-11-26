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

#include "tink/prf/internal/hmac_prf_key_creator.h"

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
#include "tink/prf/hmac_prf_key.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/prf/internal/hmac_prf_test_vectors.h"

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
  const HmacPrfKey& expected_key;
};

using HmacPrfKeyCreatorParameterizedTest = TestWithParam<TestCase>;

TEST_P(HmacPrfKeyCreatorParameterizedTest, CreateKeyWorks) {
  const HmacPrfKey& expected_key = GetParam().expected_key;

  absl::StatusOr<std::unique_ptr<Key>> key =
      CreateHmacPrfKey(expected_key.GetParameters(), std::nullopt);
  ASSERT_THAT(key, IsOk());

  const auto* hmac_prf_key = dynamic_cast<const HmacPrfKey*>(key->get());
  ASSERT_NE(hmac_prf_key, nullptr);
  EXPECT_THAT(hmac_prf_key->GetIdRequirement(), Eq(std::nullopt));
  EXPECT_THAT(hmac_prf_key->GetParameters(), Eq(expected_key.GetParameters()));
}

TEST_P(HmacPrfKeyCreatorParameterizedTest, CreateKeyTwiceYieldsDifferentKeys) {
  const HmacPrfKey& expected_key = GetParam().expected_key;

  absl::StatusOr<std::unique_ptr<Key>> key1 =
      CreateHmacPrfKey(expected_key.GetParameters(), std::nullopt);
  ASSERT_THAT(key1, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> key2 =
      CreateHmacPrfKey(expected_key.GetParameters(), std::nullopt);
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(**key1, **key2);
}

TEST_P(HmacPrfKeyCreatorParameterizedTest,
       CreateKeyWithKeyGenConfigurationWorks) {
  const HmacPrfKey& expected_key = GetParam().expected_key;
  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddKeyCreator<HmacPrfParameters>(
                  CreateHmacPrfKey, key_creator_config),
              IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key = KeyGenConfigurationImpl::CreateKey(
      expected_key.GetParameters(), std::nullopt, key_creator_config);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetParameters(), Eq(expected_key.GetParameters()));
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(std::nullopt));
}

INSTANTIATE_TEST_SUITE_P(HmacPrfKeyCreatorParameterizedTests,
                         HmacPrfKeyCreatorParameterizedTest,
                         ValuesIn<TestCase>({
                             {/*name=*/"HmacPrf32Sha1",
                              /*expected_key=*/GetHmacPrfTestVector(
                                  32, HmacPrfParameters::HashType::kSha1)
                                  .key},
                             {/*name=*/"HmacPrf40Sha256",
                              /*expected_key=*/GetHmacPrfTestVector(
                                  40, HmacPrfParameters::HashType::kSha256)
                                  .key},
                             {/*name=*/"HmacPrf20Sha384",
                              /*expected_key=*/GetHmacPrfTestVector(
                                  20, HmacPrfParameters::HashType::kSha384)
                                  .key},
                             {/*name=*/"HmacPrf100Sha512",
                              /*expected_key=*/GetHmacPrfTestVector(
                                  100, HmacPrfParameters::HashType::kSha512)
                                  .key},
                         }),
                         [](const TestParamInfo<TestCase>& info) {
                           return info.param.name;
                         });

TEST(HmacPrfKeyCreatorTest, CreateKeyWithIdRequirementFails) {
  const HmacPrfParameters& params =
      GetHmacPrfTestVector(40, HmacPrfParameters::HashType::kSha256)
          .key.GetParameters();
  EXPECT_THAT(CreateHmacPrfKey(params, 123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
