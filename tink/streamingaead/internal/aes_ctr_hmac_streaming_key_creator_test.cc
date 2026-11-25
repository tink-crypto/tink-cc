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

#include "tink/streamingaead/internal/aes_ctr_hmac_streaming_key_creator.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/partial_key_access.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"

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

const AesCtrHmacStreamingParameters& Aes128CtrHmacStreamingParameters() {
  static const absl::NoDestructor<AesCtrHmacStreamingParameters> kParameters(
      [] {
        absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
            AesCtrHmacStreamingParameters::Builder()
                .SetKeySizeInBytes(16)
                .SetDerivedKeySizeInBytes(16)
                .SetHkdfHashType(
                    AesCtrHmacStreamingParameters::HashType::kSha256)
                .SetHmacHashType(
                    AesCtrHmacStreamingParameters::HashType::kSha256)
                .SetHmacTagSizeInBytes(32)
                .SetCiphertextSegmentSizeInBytes(4096)
                .Build();
        ABSL_CHECK_OK(parameters);
        return *parameters;
      }());
  return *kParameters;
}

const AesCtrHmacStreamingParameters&
Aes256CtrHmacStreamingDerived16Parameters() {
  static const absl::NoDestructor<AesCtrHmacStreamingParameters> kParameters(
      [] {
        absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
            AesCtrHmacStreamingParameters::Builder()
                .SetKeySizeInBytes(32)
                .SetDerivedKeySizeInBytes(16)
                .SetHkdfHashType(
                    AesCtrHmacStreamingParameters::HashType::kSha512)
                .SetHmacHashType(
                    AesCtrHmacStreamingParameters::HashType::kSha512)
                .SetHmacTagSizeInBytes(20)
                .SetCiphertextSegmentSizeInBytes(4096)
                .Build();
        ABSL_CHECK_OK(parameters);
        return *parameters;
      }());
  return *kParameters;
}

const AesCtrHmacStreamingParameters& Aes256CtrHmacStreamingParameters() {
  static const absl::NoDestructor<AesCtrHmacStreamingParameters> kParameters(
      [] {
        absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
            AesCtrHmacStreamingParameters::Builder()
                .SetKeySizeInBytes(32)
                .SetDerivedKeySizeInBytes(32)
                .SetHkdfHashType(
                    AesCtrHmacStreamingParameters::HashType::kSha512)
                .SetHmacHashType(
                    AesCtrHmacStreamingParameters::HashType::kSha512)
                .SetHmacTagSizeInBytes(32)
                .SetCiphertextSegmentSizeInBytes(4096)
                .Build();
        ABSL_CHECK_OK(parameters);
        return *parameters;
      }());
  return *kParameters;
}

struct TestCase {
  std::string name;
  const AesCtrHmacStreamingParameters& parameters;
};

using AesCtrHmacStreamingKeyCreatorParameterizedTest = TestWithParam<TestCase>;

TEST_P(AesCtrHmacStreamingKeyCreatorParameterizedTest, CreateKeyWorks) {
  const AesCtrHmacStreamingParameters& parameters = GetParam().parameters;

  absl::StatusOr<std::unique_ptr<Key>> key =
      CreateAesCtrHmacStreamingKey(parameters, std::nullopt);
  ASSERT_THAT(key, IsOk());

  const auto* streaming_key =
      dynamic_cast<const AesCtrHmacStreamingKey*>(key->get());
  ASSERT_NE(streaming_key, nullptr);
  EXPECT_THAT(streaming_key->GetIdRequirement(), Eq(std::nullopt));
  EXPECT_THAT(streaming_key->GetParameters(), Eq(parameters));
  EXPECT_THAT(streaming_key->GetInitialKeyMaterial(GetPartialKeyAccess())
                  .Get(InsecureSecretKeyAccess::Get()),
              SizeIs(parameters.KeySizeInBytes()));
}

TEST_P(AesCtrHmacStreamingKeyCreatorParameterizedTest,
       CreateKeyTwiceYieldsDifferentKeys) {
  const AesCtrHmacStreamingParameters& parameters = GetParam().parameters;

  absl::StatusOr<std::unique_ptr<Key>> key1 =
      CreateAesCtrHmacStreamingKey(parameters, std::nullopt);
  ASSERT_THAT(key1, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> key2 =
      CreateAesCtrHmacStreamingKey(parameters, std::nullopt);
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(**key1, **key2);
}

TEST_P(AesCtrHmacStreamingKeyCreatorParameterizedTest,
       CreateKeyWithKeyGenConfigurationWorks) {
  const AesCtrHmacStreamingParameters& parameters = GetParam().parameters;
  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(
      KeyGenConfigurationImpl::AddKeyCreator<AesCtrHmacStreamingParameters>(
          CreateAesCtrHmacStreamingKey, key_creator_config),
      IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key = KeyGenConfigurationImpl::CreateKey(
      parameters, std::nullopt, key_creator_config);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetParameters(), Eq(parameters));
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(std::nullopt));
}

INSTANTIATE_TEST_SUITE_P(
    AesCtrHmacStreamingKeyCreatorParameterizedTests,
    AesCtrHmacStreamingKeyCreatorParameterizedTest,
    ValuesIn<TestCase>({
        {/*name=*/"Aes128CtrHmacStreaming",
         /*parameters=*/Aes128CtrHmacStreamingParameters()},
        {/*name=*/"Aes256CtrHmacStreamingDerived16",
         /*parameters=*/Aes256CtrHmacStreamingDerived16Parameters()},
        {/*name=*/"Aes256CtrHmacStreaming",
         /*parameters=*/Aes256CtrHmacStreamingParameters()},
    }),
    [](const TestParamInfo<TestCase>& info) { return info.param.name; });

TEST(AesCtrHmacStreamingKeyCreatorTest, CreateKeyWithIdRequirementFails) {
  EXPECT_THAT(
      CreateAesCtrHmacStreamingKey(Aes256CtrHmacStreamingParameters(), 123),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
