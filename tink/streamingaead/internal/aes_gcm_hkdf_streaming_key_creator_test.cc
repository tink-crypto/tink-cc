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

#include "tink/streamingaead/internal/aes_gcm_hkdf_streaming_key_creator.h"

#include <memory>
#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"
#include "tink/streamingaead/internal/testing/aes_gcm_hkdf_streaming_test_vectors.h"
#include "tink/streamingaead/internal/testing/streamingaead_test_vector.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using AesGcmHkdfStreamingKeyCreatorParameterizedTest =
    TestWithParam<StreamingAeadTestVector>;

TEST_P(AesGcmHkdfStreamingKeyCreatorParameterizedTest, CreateKeyWorks) {
  const auto* expected_key = dynamic_cast<const AesGcmHkdfStreamingKey*>(
      GetParam().streamingaead_key.get());
  ASSERT_NE(expected_key, nullptr);

  absl::StatusOr<std::unique_ptr<Key>> key =
      CreateAesGcmHkdfStreamingKey(expected_key->GetParameters(), std::nullopt);
  ASSERT_THAT(key, IsOk());

  const auto* streaming_key =
      dynamic_cast<const AesGcmHkdfStreamingKey*>(key->get());
  ASSERT_NE(streaming_key, nullptr);
  EXPECT_THAT(streaming_key->GetIdRequirement(), Eq(std::nullopt));
  EXPECT_THAT(streaming_key->GetParameters(),
              Eq(expected_key->GetParameters()));
}

TEST_P(AesGcmHkdfStreamingKeyCreatorParameterizedTest,
       CreateKeyTwiceYieldsDifferentKeys) {
  const auto* expected_key = dynamic_cast<const AesGcmHkdfStreamingKey*>(
      GetParam().streamingaead_key.get());
  ASSERT_NE(expected_key, nullptr);

  absl::StatusOr<std::unique_ptr<Key>> key1 =
      CreateAesGcmHkdfStreamingKey(expected_key->GetParameters(), std::nullopt);
  ASSERT_THAT(key1, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> key2 =
      CreateAesGcmHkdfStreamingKey(expected_key->GetParameters(), std::nullopt);
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(**key1, **key2);
}

TEST_P(AesGcmHkdfStreamingKeyCreatorParameterizedTest,
       CreateKeyWithKeyGenConfigurationWorks) {
  const auto* expected_key = dynamic_cast<const AesGcmHkdfStreamingKey*>(
      GetParam().streamingaead_key.get());
  ASSERT_NE(expected_key, nullptr);
  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(
      KeyGenConfigurationImpl::AddKeyCreator<AesGcmHkdfStreamingParameters>(
          CreateAesGcmHkdfStreamingKey, key_creator_config),
      IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key = KeyGenConfigurationImpl::CreateKey(
      expected_key->GetParameters(), std::nullopt, key_creator_config);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetParameters(), Eq(expected_key->GetParameters()));
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(std::nullopt));
}

INSTANTIATE_TEST_SUITE_P(AesGcmHkdfStreamingKeyCreatorParameterizedTests,
                         AesGcmHkdfStreamingKeyCreatorParameterizedTest,
                         ValuesIn(CreateAesGcmHkdfStreamingTestVectors()));

TEST(AesGcmHkdfStreamingKeyCreatorTest, CreateKeyWithIdRequirementFails) {
  const auto* expected_key = dynamic_cast<const AesGcmHkdfStreamingKey*>(
      GetAesGcmHkdfStreamingTestVector(32).streamingaead_key.get());
  ASSERT_NE(expected_key, nullptr);
  EXPECT_THAT(CreateAesGcmHkdfStreamingKey(expected_key->GetParameters(), 123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
