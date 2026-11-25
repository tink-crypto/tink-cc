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

#include "tink/mac/internal/aes_cmac_key_creator.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/mac/aes_cmac_key.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/mac/internal/aes_cmac_test_vectors.h"
#include "tink/partial_key_access.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::SizeIs;
using ::testing::TestParamInfo;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using AesCmacKeyCreatorParameterizedTest = TestWithParam<TinkAesCmacTestVector>;

TEST_P(AesCmacKeyCreatorParameterizedTest, CreateKeyWorks) {
  const AesCmacKey& expected_key = GetParam().key;

  absl::StatusOr<std::unique_ptr<Key>> key = CreateAesCmacKey(
      expected_key.GetParameters(), expected_key.GetIdRequirement());
  ASSERT_THAT(key, IsOk());

  const auto* aes_cmac_key = dynamic_cast<const AesCmacKey*>(key->get());
  ASSERT_NE(aes_cmac_key, nullptr);
  EXPECT_THAT(aes_cmac_key->GetIdRequirement(),
              Eq(expected_key.GetIdRequirement()));
  EXPECT_THAT(aes_cmac_key->GetParameters(), Eq(expected_key.GetParameters()));
  EXPECT_THAT(aes_cmac_key->GetKeyBytes(GetPartialKeyAccess())
                  .Get(InsecureSecretKeyAccess::Get()),
              SizeIs(expected_key.GetParameters().KeySizeInBytes()));
  EXPECT_THAT(aes_cmac_key->GetOutputPrefix(),
              Eq(expected_key.GetOutputPrefix()));
}

TEST_P(AesCmacKeyCreatorParameterizedTest, CreateKeyTwiceYieldsDifferentKeys) {
  const AesCmacKey& expected_key = GetParam().key;

  absl::StatusOr<std::unique_ptr<Key>> key1 = CreateAesCmacKey(
      expected_key.GetParameters(), expected_key.GetIdRequirement());
  ASSERT_THAT(key1, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> key2 = CreateAesCmacKey(
      expected_key.GetParameters(), expected_key.GetIdRequirement());
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(**key1, **key2);
}

TEST_P(AesCmacKeyCreatorParameterizedTest,
       CreateKeyWithKeyGenConfigurationWorks) {
  const AesCmacKey& expected_key = GetParam().key;
  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddKeyCreator<AesCmacParameters>(
                  CreateAesCmacKey, key_creator_config),
              IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key = KeyGenConfigurationImpl::CreateKey(
      expected_key.GetParameters(), expected_key.GetIdRequirement(),
      key_creator_config);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetParameters(), Eq(expected_key.GetParameters()));
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(expected_key.GetIdRequirement()));
}

INSTANTIATE_TEST_SUITE_P(AesCmacKeyCreatorParameterizedTests,
                         AesCmacKeyCreatorParameterizedTest,
                         ValuesIn(AesCmacTestVectors()),
                         [](const TestParamInfo<TinkAesCmacTestVector>& info) {
                           return info.param.test_name;
                         });

TEST(AesCmacKeyCreatorTest, CreateKeyTinkWithoutIdRequirementFails) {
  absl::StatusOr<AesCmacParameters> tink_params = AesCmacParameters::Create(
      /*key_size_in_bytes=*/32, /*cryptographic_tag_size_in_bytes=*/16,
      AesCmacParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());
  EXPECT_THAT(CreateAesCmacKey(*tink_params, std::nullopt),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(AesCmacKeyCreatorTest, CreateKeyNoPrefixWithIdRequirementFails) {
  absl::StatusOr<AesCmacParameters> no_prefix_params =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_params, IsOk());
  EXPECT_THAT(CreateAesCmacKey(*no_prefix_params, 123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
