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

#include "tink/aead/internal/aes_gcm_siv_key_creator.h"

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
#include "tink/aead/aes_gcm_siv_key.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
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

const AesGcmSivParameters& Aes128GcmSivTinkParameters() {
  static const absl::NoDestructor<AesGcmSivParameters> kParameters([] {
    absl::StatusOr<AesGcmSivParameters> parameters =
        AesGcmSivParameters::Create(16, AesGcmSivParameters::Variant::kTink);
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

const AesGcmSivParameters& Aes128GcmSivNoPrefixParameters() {
  static const absl::NoDestructor<AesGcmSivParameters> kParameters([] {
    absl::StatusOr<AesGcmSivParameters> parameters =
        AesGcmSivParameters::Create(16,
                                    AesGcmSivParameters::Variant::kNoPrefix);
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

const AesGcmSivParameters& Aes256GcmSivTinkParameters() {
  static const absl::NoDestructor<AesGcmSivParameters> kParameters([] {
    absl::StatusOr<AesGcmSivParameters> parameters =
        AesGcmSivParameters::Create(32, AesGcmSivParameters::Variant::kTink);
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

const AesGcmSivParameters& Aes256GcmSivNoPrefixParameters() {
  static const absl::NoDestructor<AesGcmSivParameters> kParameters([] {
    absl::StatusOr<AesGcmSivParameters> parameters =
        AesGcmSivParameters::Create(32,
                                    AesGcmSivParameters::Variant::kNoPrefix);
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

struct TestVector {
  std::string name;
  const AesGcmSivParameters& parameters;
  std::optional<int> id_requirement;
  std::string expected_prefix;
};

class AesGcmSivKeyCreatorTest : public TestWithParam<TestVector> {};

TEST_P(AesGcmSivKeyCreatorTest, CreateKey) {
  const TestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<Key>> key =
      CreateAesGcmSivKey(test_vector.parameters, test_vector.id_requirement);
  ASSERT_THAT(key, IsOk());
  AesGcmSivKey* aes_gcm_siv_key = dynamic_cast<AesGcmSivKey*>(key->get());
  ASSERT_NE(aes_gcm_siv_key, nullptr);
  if (test_vector.id_requirement.has_value()) {
    EXPECT_EQ(aes_gcm_siv_key->GetIdRequirement(),
              test_vector.id_requirement.value());
  } else {
    EXPECT_EQ(aes_gcm_siv_key->GetIdRequirement(), std::nullopt);
  }
  EXPECT_EQ(aes_gcm_siv_key->GetParameters(), test_vector.parameters);
  EXPECT_THAT(aes_gcm_siv_key->GetKeyBytes(GetPartialKeyAccess())
                  .Get(InsecureSecretKeyAccess::Get()),
              SizeIs(test_vector.parameters.KeySizeInBytes()));

  EXPECT_EQ(aes_gcm_siv_key->GetOutputPrefix(), test_vector.expected_prefix);
}

TEST(AesGcmSivKeyCreatorTest, CreateKeyFailsWithInvalidKeyId) {
  EXPECT_THAT(CreateAesGcmSivKey(Aes128GcmSivTinkParameters(), std::nullopt),
              Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    AesGcmSivKeyCreatorTest, AesGcmSivKeyCreatorTest,
    testing::ValuesIn<TestVector>({
        {/*name=*/"Aes128GcmSivTinkParameters",
         /*parameters=*/Aes128GcmSivTinkParameters(),
         /*id_requirement=*/1,
         /*expected_prefix=*/std::string({0x01, 0x00, 0x00, 0x00, 0x01})},
        {/*name=*/"Aes128GcmSivNoPrefixParameters",
         /*parameters=*/Aes128GcmSivNoPrefixParameters(), std::nullopt,
         /*expected_prefix=*/""},
        {/*name=*/"Aes256GcmSivTinkParameters",
         /*parameters=*/Aes256GcmSivTinkParameters(),
         /*id_requirement=*/2,
         /*expected_prefix=*/std::string({0x01, 0x00, 0x00, 0x00, 0x02})},
        {/*name=*/"Aes256GcmSivNoPrefixParameters",
         /*parameters=*/Aes256GcmSivNoPrefixParameters(), std::nullopt,
         /*expected_prefix=*/""},
    }),
    [](const testing::TestParamInfo<AesGcmSivKeyCreatorTest::ParamType>& info) {
      return info.param.name;
    });

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
