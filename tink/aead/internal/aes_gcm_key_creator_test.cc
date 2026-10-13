// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, embodiment or
// conditions of any kind, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/aead/internal/aes_gcm_key_creator.h"

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
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::TestWithParam;

const AesGcmParameters& Aes128GcmTinkParameters() {
  static const absl::NoDestructor<AesGcmParameters> kAes128GcmParameters([] {
    absl::StatusOr<AesGcmParameters> parameters =
        AesGcmParameters::Builder()
            .SetIvSizeInBytes(12)
            .SetKeySizeInBytes(16)
            .SetTagSizeInBytes(16)
            .SetVariant(AesGcmParameters::Variant::kTink)
            .Build();
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kAes128GcmParameters;
}

const AesGcmParameters& Aes128GcmNoPrefixParameters() {
  static const absl::NoDestructor<AesGcmParameters> kAes128GcmParameters([] {
    absl::StatusOr<AesGcmParameters> parameters =
        AesGcmParameters::Builder()
            .SetIvSizeInBytes(12)
            .SetKeySizeInBytes(16)
            .SetTagSizeInBytes(16)
            .SetVariant(AesGcmParameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kAes128GcmParameters;
}

const AesGcmParameters& Aes256GcmTinkParameters() {
  static const absl::NoDestructor<AesGcmParameters> kAes256GcmParameters([] {
    absl::StatusOr<AesGcmParameters> parameters =
        AesGcmParameters::Builder()
            .SetIvSizeInBytes(12)
            .SetKeySizeInBytes(32)
            .SetTagSizeInBytes(16)
            .SetVariant(AesGcmParameters::Variant::kTink)
            .Build();
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kAes256GcmParameters;
}

const AesGcmParameters& Aes256GcmNoPrefixParameters() {
  static const absl::NoDestructor<AesGcmParameters> kAes256GcmParameters([] {
    absl::StatusOr<AesGcmParameters> parameters =
        AesGcmParameters::Builder()
            .SetIvSizeInBytes(12)
            .SetKeySizeInBytes(32)
            .SetTagSizeInBytes(16)
            .SetVariant(AesGcmParameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kAes256GcmParameters;
}

struct TestVector {
  std::string name;
  const AesGcmParameters& parameters;
  std::optional<int> id_requirement;
  std::string expected_prefix;
};

class AesGcmKeyCreatorTest : public TestWithParam<TestVector> {};

TEST_P(AesGcmKeyCreatorTest, CreateKey) {
  const TestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<Key>> key =
      CreateAesGcmKey(test_vector.parameters, test_vector.id_requirement);
  ASSERT_THAT(key, IsOk());
  AesGcmKey* aes_gcm_key = dynamic_cast<AesGcmKey*>(key->get());
  ASSERT_NE(aes_gcm_key, nullptr);
  if (test_vector.id_requirement.has_value()) {
    EXPECT_EQ(aes_gcm_key->GetIdRequirement(),
              test_vector.id_requirement.value());
  } else {
    EXPECT_EQ(aes_gcm_key->GetIdRequirement(), std::nullopt);
  }
  EXPECT_EQ(aes_gcm_key->GetParameters(), test_vector.parameters);
  EXPECT_THAT(aes_gcm_key->GetKeyBytes(GetPartialKeyAccess())
                  .Get(InsecureSecretKeyAccess::Get()),
              SizeIs(test_vector.parameters.KeySizeInBytes()));

  EXPECT_EQ(aes_gcm_key->GetOutputPrefix(), test_vector.expected_prefix);
}

TEST(AesGcmKeyCreatorTest, CreateKeyFailsWithInvalidKeyId) {
  EXPECT_THAT(CreateAesGcmKey(Aes128GcmTinkParameters(), std::nullopt),
              Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    AesGcmKeyCreatorTest, AesGcmKeyCreatorTest,
    testing::ValuesIn<TestVector>({
        {/*name=*/"Aes128GcmTinkParameters",
         /*parameters=*/Aes128GcmTinkParameters(),
         /*id_requirement=*/1,
         /*expected_prefix=*/std::string({0x01, 0x00, 0x00, 0x00, 0x01})},
        {/*name=*/"Aes128GcmNoPrefixParameters",
         /*parameters=*/Aes128GcmNoPrefixParameters(), std::nullopt,
         /*expected_prefix=*/""},
        {/*name=*/"Aes256GcmTinkParameters",
         /*parameters=*/Aes256GcmTinkParameters(),
         /*id_requirement=*/2,
         /*expected_prefix=*/std::string({0x01, 0x00, 0x00, 0x00, 0x02})},
        {/*name=*/"Aes256GcmNoPrefixParameters",
         /*parameters=*/Aes256GcmNoPrefixParameters(), std::nullopt,
         /*expected_prefix=*/""},
    }),
    [](const testing::TestParamInfo<AesGcmKeyCreatorTest::ParamType>& info) {
      return info.param.name;
    });

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
