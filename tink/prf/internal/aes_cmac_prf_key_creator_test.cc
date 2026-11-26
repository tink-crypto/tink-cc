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

#include "tink/prf/internal/aes_cmac_prf_key_creator.h"

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
#include "tink/prf/aes_cmac_prf_key.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/prf/internal/aes_cmac_prf_test_vectors.h"

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
  const AesCmacPrfKey& expected_key;
};

using AesCmacPrfKeyCreatorParameterizedTest = TestWithParam<TestCase>;

TEST_P(AesCmacPrfKeyCreatorParameterizedTest, CreateKeyWorks) {
  const AesCmacPrfKey& expected_key = GetParam().expected_key;

  absl::StatusOr<std::unique_ptr<Key>> key =
      CreateAesCmacPrfKey(expected_key.GetParameters(), std::nullopt);
  ASSERT_THAT(key, IsOk());

  const auto* aes_cmac_prf_key = dynamic_cast<const AesCmacPrfKey*>(key->get());
  ASSERT_NE(aes_cmac_prf_key, nullptr);
  EXPECT_THAT(aes_cmac_prf_key->GetIdRequirement(), Eq(std::nullopt));
  EXPECT_THAT(aes_cmac_prf_key->GetParameters(),
              Eq(expected_key.GetParameters()));
}

TEST_P(AesCmacPrfKeyCreatorParameterizedTest,
       CreateKeyTwiceYieldsDifferentKeys) {
  const AesCmacPrfKey& expected_key = GetParam().expected_key;

  absl::StatusOr<std::unique_ptr<Key>> key1 =
      CreateAesCmacPrfKey(expected_key.GetParameters(), std::nullopt);
  ASSERT_THAT(key1, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> key2 =
      CreateAesCmacPrfKey(expected_key.GetParameters(), std::nullopt);
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(**key1, **key2);
}

TEST_P(AesCmacPrfKeyCreatorParameterizedTest,
       CreateKeyWithKeyGenConfigurationWorks) {
  const AesCmacPrfKey& expected_key = GetParam().expected_key;
  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddKeyCreator<AesCmacPrfParameters>(
                  CreateAesCmacPrfKey, key_creator_config),
              IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key = KeyGenConfigurationImpl::CreateKey(
      expected_key.GetParameters(), std::nullopt, key_creator_config);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetParameters(), Eq(expected_key.GetParameters()));
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(std::nullopt));
}

INSTANTIATE_TEST_SUITE_P(AesCmacPrfKeyCreatorParameterizedTests,
                         AesCmacPrfKeyCreatorParameterizedTest,
                         ValuesIn<TestCase>({
                             {/*name=*/"AesCmacPrf16",
                              /*expected_key=*/GetAesCmacPrfTestVector(16).key},
                             {/*name=*/"AesCmacPrf32",
                              /*expected_key=*/GetAesCmacPrfTestVector(32).key},
                         }),
                         [](const TestParamInfo<TestCase>& info) {
                           return info.param.name;
                         });

TEST(AesCmacPrfKeyCreatorTest, CreateKeyWithIdRequirementFails) {
  const AesCmacPrfParameters& params =
      GetAesCmacPrfTestVector(32).key.GetParameters();
  EXPECT_THAT(CreateAesCmacPrfKey(params, 123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
